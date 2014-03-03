from oic.utils.authn.user import UserAuthnMethod
from idproxy.client.sp.handler import UserInfoSpHandler

__author__ = 'haho0032'

#Returns user_info for the designated authentication method. In the proxy is different authentication methods
#considered to be different users even though it is the same person that have several accounts.
class UserInfoAuthHandler(object):
    def __init__(self, ophandler, user_info_auth_map):
        """
        Returns the attributes collected by the SpHandler.
        :param ophandler: The OpHandler class object.
        :param auth_user_info_map: A dictionary with auth as key and user_info object as value.
        """
        self.ophandler = ophandler
        self.user_info_auth_map = user_info_auth_map

    def set_saml_response(self, samlresponse):
        """
        Sets the kind of user information response the pyOpSamlProxy.client.sp.handler.UserInfoSpHandler instance
        should give. If samlresponse is true, the information sent to the client will be the compelete response from
        the Idp. If samlresponse is false the information retrieved from the IdP will be mapped to OpenId connect
        userinfo endpoint.
        :param samlresponse: See above.
        """
        for key, value in self.user_info_auth_map.items():
            if type(self.user_info_auth_map[key]) == UserInfoSpHandler:
                self.user_info_auth_map[key].set_samlresponse(samlresponse)

    def __call__(self, userid, user_info_claims=None, **kwargs):
        """
        Returns the user_info for the designated user_info class for the authentication performed by the user.
        :param userid: Unique identifier for the user.
        :param user_info_claims: Oic claims for user info.
        :param kwargs: Not used.
        :return: User info as a key value dictionary.
        """
        return self.user_info_auth_map[self.ophandler.get_op_handler_cache(userid).auth](userid, user_info_claims, **kwargs)


#This class is a authentication class for oic.oic.provider.Provider.
#This specific class can take any number of authentication methods and then execute them in order.
#All authentications must succeed to grant the user access to the OP.
class MultipleAuthHandler(UserAuthnMethod):
    #Session name for the authentication method counter.
    MULTIPLEAUTHHANDLER_COUNTER = "MULTIPLEAUTHHANDLER_COUNTER"
    def __init__(self, auth_handler_list):
        """
        Constructor.
        :param auth_handler_list: An ordered list of authentication classes (implementations of UserAuthnMethod).
        """
        UserAuthnMethod.__init__(self, "")
        self.auth_handler_list = auth_handler_list
        #Amount of authentications that has to be performed.
        self.steps = len(auth_handler_list) - 1
        #Must be updated on the side.
        self.ophandler = None

    def set_srv(self, srv):
        self.srv = srv
        if self.authn_helper is not None:
            self.authn_helper.srv = srv
        try:
            for item in self.auth_handler_list:
                if "set_srv" in dir(item):
                    item.set_srv(srv)
                else:
                    item.srv = srv
        except:
            pass


    def __call__(self, **authn_args):
        """
        Call the next authentication class in the list.
        :param authn_args: Passed on to the "real" authentication class.
        :return: Response from the authentication class used.
        """
        step = 0
        if "MULTIPLEAUTHHANDLER_COUNTER" not in self.ophandler.session:
            self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"] = step
        else:
            step = self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"]
        authn = self.auth_handler_list[step]
        authn.srv = self.srv
        resp = authn(**authn_args)
        return resp

    def verify(self, request, **kwargs):
        """
        Verifies that the authentication performed by the user was correct.
        If the verification was correct and this is not the last authentication that must be performed, then
        the user will be passed on to the next authentication to be performed.
        :param request: Passed on to the "real" authentication class.
        :param kwargs:  Passed on to the "real" authentication class.
        :return:
        """
        step = self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"]
        authn = self.auth_handler_list[step]
        authn.srv = self.srv
        resp = authn.verify(request, **kwargs)
        if resp._status == "302 Found":
            if step < self.steps:
                new_headers = []
                #Remove the authentication cookie if it exists to move on to the next authentication method
                #in the list.
                for tuple in resp.headers:
                    append = True
                    if tuple is not None and tuple[0] == 'Set-Cookie':
                        try:
                            identity = authn.authenticated_as(tuple[1])
                            if identity["uid"] is not None:
                                self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"] = \
                                    self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"] + 1
                                append = False
                        except:
                            pass
                    if append:
                        new_headers.append(tuple)
                resp.headers = new_headers
            else:
                #Make sure the user never can skip a step.
                self.ophandler.session["MULTIPLEAUTHHANDLER_COUNTER"] = 0
        return resp

