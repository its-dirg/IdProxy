import hashlib
import importlib
import datetime

from dirg_util.http_util import HttpHandler
from saml2 import BINDING_HTTP_POST
from saml2.metadata import create_metadata_string
from saml2.response import AuthnResponse


__author__ = 'haho0032'
import json
import logging
import base64
import time
import re
from saml2.client import Saml2Client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.http_util import Redirect
from oic.utils.http_util import Unauthorized
from idproxy.client.sp.util import SSO, ACS, Cache
from Crypto import Random
from saml2.s_utils import sid

#Log class for the SP.
logger = logging.getLogger(__name__)


#This is a cache object for data retrieved by a specific user from a specific IdP.
class SpHandlerCache(object):
    def __init__(self):
        """
        Constructor.
        """
        #When the attributes are timed out by the IdP.
        self.timeout = None
        #Attributes returned from the IdP. A dictionary.
        self.attributes = None
        #True if the user have been authenticated by a IdP.
        self.auth = False
        #The unique identifier from the Idp.
        self.uid = None
        #The complete assertion
        self.assertion = None
        #The complete encrypted assertion
        self.encrypted_assertion = None
        #Complete authn response
        self.authnresponse = None
        #Namespaces in the response as a dictionary.
        self.namespace_dict = None


#SPHandler represent a SP client and acts separate on the application server.
#The front end server can redirect to the sp to perform authentication.
#The method handleIdPResponse will give the correct response after authentication.
#The class SPAuthnMethodHandler is used to add SP authentication to the op server.
#The class UserInfoSpHandler is used to make it possible to return the attributes collected by SP for the op_server.
class SpHandler:
    #The session name that holds the pyOpSamlProxy.client.sp.util.Cache object for the user.
    SPHANDLERSSOCACHE = "sphandlerssocache"
    #The session name that holds the sub (read unique user id) returned from the IdP.
    SPHANDLERFORSUB = "sub"

    SPHANDLERFORUID = "uid"

    SPHANDLERVERIFYTYPE = "SPHANDLERVERIFYTYPE"

    def __init__(self, sp_logger, args):
        """
        Constructor for the SpHandler.
        :param sp_logger: A logger.
        """
        #Metadata for the SP
        self.sp_metadata = create_metadata_string(args.spconf + ".py", None, args.valid, args.cert, args.keyfile,
                                                  args.id_sp, args.name_sp, args.sign)
        #Log class. (see import logging)
        self.logger = sp_logger
        #Configurations for the SP handler. (pyOpSamlProxy.client.sp.conf)
        self.sp_conf = importlib.import_module(args.spconf)  #pyOpSamlProxy.client.sp.conf
        #Name of the configuration file. See above.
        self.sp_conf_name = self.sp_conf.WORKING_DIR + args.spconf
        #SP configuration object. (See project pysaml2; saml2.client.Saml2Client)
        self.sp = Saml2Client(config_file="%s" % self.sp_conf_name)
        #Extra arguments for the pyOpSamlProxy.client.sp.util.SSO object.
        self.args = {}
        #URL to SAML discovery server.
        self.args["discosrv"] = self.sp_conf.DISCOSRV
        #URL to SAML WAYF server.
        self.args["wayf"] = self.sp_conf.WAYF
        #URL to op server authorization when the SP have been authenticated.
        #TODO have to be changed when Saml to Saml is implemented.
        self.authorization_url = "%s/authorization" % self.sp_conf.ISSUER
        #Handles the SAML authentication for an op server.
        self.authnmethod = SPAuthnMethodHandler(None, self.sp_conf.SPVERIFYBASE, self.authorization_url)
        #Handles SAML authentication for an IdP server.
        # Setup performed by pyOpSamlProxy.provider.idp.handler.IdPHandler.
        self.sp_authentication = None
        #Handles the user info response with Saml attributes.
        self.userinfo = UserInfoSpHandler(self.sp_conf.OPENID2SAMLMAP, self)
        #The handler for the op server. Must be set after creation
        #This must be the instance of the class pyOpSamlProxy.provider.op.handler.OpHandler.
        self.ophandler = None
        #Contains the user cache for the SpHandler, like collected IdP attributes.
        #Dictionary where userid is key and value is an instance of the class
        #pyOpSamlProxy.client.sp.handler.SpHandlerCache
        self.sphandlercache = self.sp_conf.CACHE
        self.certificate_cache_name = "CERTIFICATE_CACHE"
        self.certificate_cookie_name = sid()
        self.certificate_cookie_seed = sid()

    @staticmethod
    def verify_timeout(timeout):
        """
        Verifies if a timeout should occur. The method is static since it do not need the object to work.
        :param timeout: The last time before a timeout should occur.
                        Floating point number expressed in seconds since the epoch, in UTC
        :return: True if a timeout occurs, otherwise false.
        """
        if timeout is None or timeout < time.time():
            return True
        return False

    def clear_sp_handler_cache(self, environ, session):
        """
        Clears the the SpHandlerCache for the current user. All data retrieved from the IdP is cleared for the user.
        :param environ: WSGI enviroment.
        :param session: The current session for the user. (pyOpSamlProxy.util.session.Session)
        """
        sub = self.get_sub(environ, session)
        self.set_sp_handler_cache(sub, None)

    def get_sp_handler_cache(self, sub):
        """
        Retrieves the cache for the SpHandler cache for a given user.
        :param sub: The unique identifier for a user.
        :return: None if the cache do not exist otherwise the cache. (pyOpSamlProxy.client.sp.handler.SpHandlerCache)
        """
        if sub not in self.sphandlercache:
            return None
        return self.sphandlercache[sub]

    def set_sp_handler_cache(self, sub, sphandlercache):
        """
        Sets the SpHandlerCache for a given user.
        :param sub:  The unique identifier for a user.
        :param sphandlercache: The cache object to be saved. (pyOpSamlProxy.client.sp.handler.SpHandlerCache)
        """
        self.sphandlercache[sub] = sphandlercache

    def get_sub(self, environ, session):
        """
        Gets the unique identifier for a user either from the session or the accesstoken.
        If the users web browser is used, then the sub is in the session, but if a call is made directly from
        a server the the sub is retrieved with the access token for the op server. Access token is always used
        before the session.
        :param environ: The WSGI enviroment.
        :param session: The current session for the user. (pyOpSamlProxy.util.session.Session)
        :return: The unique identifier for a user.
        """
        #TODO this must be updated for Saml to Saml.
        sub = None
        if self.ophandler is not None:
            sub = self.ophandler.get_sub_from_accesstoken(environ)
        if sub is None:
            if session is not None and SpHandler.SPHANDLERFORSUB in session:
                sub = session[SpHandler.SPHANDLERFORSUB]
        return sub

    def verify_sp_user_validity(self, session, environ, path):
        """
        Verifies if the attributes collected with Sp from a IdP is still valid.
        If the attributes are no longer valid, then invalidate the performed login.
        :param path: The requested path.
        :param session: The current session for the user. (pyOpSamlProxy.util.session.Session)
        :param environ: WSGI environment.
        :return: The updated environ object.
        """
        if not self.verify_sp_requests(path):
            sp_handler_cache = self.get_sp_handler_cache(self.get_sub(environ, session))
            if sp_handler_cache is not None:
                if sp_handler_cache.auth:
                    if self.verify_timeout(sp_handler_cache.timeout) or sp_handler_cache.attributes is None:
                        #TODO This is not enough for Saml to Saml
                         if self.ophandler is not None:
                            self.ophandler.filter_auth_cookie(environ)
                return environ
        return environ

    def verify_sp_requests(self, path):
        """
        Verifies if the sp is responsible for handling the request.
        :param path: The requested path.
        :return: True if this class should handle this request, otherwise false.
        """
        if path == "sp_metadata":
            return True
        if re.search(self.sp_conf.SPVERIFYBASE, path):
            return True
        for regex in self.sp_conf.ASCVERIFYPOSTLIST:
            match = re.search(regex, path)
            if match is not None:
                return True
        for regex in self.sp_conf.ASCVERIFYREDIRECTLIST:
            match = re.search(regex, path)
            if match is not None:
                return True
        return False

    def handle_response_to_op_handler(self, response, cookie, session):
        uid = self.handle_idp_response(response, cookie, session)
        session[SpHandler.SPHANDLERFORSUB] = uid
        return self.authnmethod.authn_redirect(uid, cookie)

    def handle_response_to_idp_handler(self, response, cookie, session, environ):
        uid = self.handle_idp_response(response, cookie, session)
        session[SpHandler.SPHANDLERFORUID] = uid
        return self.sp_authentication.authn_redirect(environ)

    def certificate_cache(self):
        if self.certificate_cache_name not in self.sphandlercache:
            self.sphandlercache[self.certificate_cache_name] = {}
            self.sphandlercache[self.certificate_cache_name + "clear"] = datetime.datetime.now() + \
                                                                         datetime.timedelta(minutes=
                                                                                            self.sp_conf.CERT_TIMEOUT)
        elif self.sphandlercache[self.certificate_cache_name + "clear"] < datetime.datetime.now():
            del_key_list = []
            for key, value in self.sphandlercache[self.certificate_cache_name].iteritems():
                if not (value["timeout"] > datetime.datetime.now()):
                    del_key_list.append(key)
            for key in del_key_list:
                del self.sphandlercache[self.certificate_cache_name][key]
        return self.sphandlercache[self.certificate_cache_name]

    def add_certificate_to_cache(self, certificate_str):
        _sid = sid()
        while _sid in self.certificate_cache():
            _sid = sid()
        cache = self.certificate_cache()
        cache[_sid] = {
            "timeout": datetime.datetime.now() + datetime.timedelta(minutes=self.sp_conf.CERT_TIMEOUT),
            "cert": base64.b64encode(certificate_str)
        }
        self.sphandlercache[self.certificate_cache_name] = cache
        return _sid

    def certificate_from_cache(self, uid):
        if uid in self.certificate_cache():
            return base64.b64decode(self.certificate_cache()[uid]["cert"])
        return None

    def handle_idp_response(self, response, cookie, session):
        """
        Takes care of the response from an Idp and saves the users attributes in a timed cache.
        Gives the correct response for the op server.
        :param response: Saml response. (see project pysaml2 saml2.response.AuthnResponse)
        :param cookie: The cookies sent by the client. A cookie string, same as environ["HTTP-COOKIE"]
        :param session: The current session for the user. (pyOpSamlProxy.util.session.Session)
        :return: A correct response according to the op server. This is a redirect URL to the authorization endpoint.
        """

        uid = response.assertion.subject.name_id.text

        if self.sp_conf.ANONYMIZE:
            uid = hashlib.sha256(uid + self.sp_conf.ANONYMIZE_SALT).hexdigest()
            if 'eduPersonPrincipalName' in response.ava:
                eppn = response.ava['eduPersonPrincipalName']
                if type(eppn) is list:
                    eppn_list = []
                    for eppn_value in eppn:
                        eppn_list.append(hashlib.sha256(eppn_value + self.sp_conf.ANONYMIZE_SALT).hexdigest() +
                                         "@" + self.sp_conf.HOST)
                    eppn = eppn_list
                else:
                    eppn = hashlib.sha512(eppn + self.sp_conf.ANONYMIZE_SALT).hexdigest() + "@" + self.sp_conf.HOST
                response.ava['eduPersonPrincipalName'] = eppn

        sp_handler_cache = self.get_sp_handler_cache(uid)
        if sp_handler_cache is None:
            sp_handler_cache = SpHandlerCache()
        sp_handler_cache.uid = uid
        sp_handler_cache.timeout = response.not_on_or_after
        sp_handler_cache.attributes = response.ava
        sp_handler_cache.auth = True
        self.set_sp_handler_cache(uid, sp_handler_cache)
        return uid

    def handle_sp_requests(self, environ, start_response, path, session):
        """
        Handles all url:s that are intended for the sp.
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: The response created by underlying methods. For example;
                 Redirect to a discovery server.
                 Redirect to a SAML Idp.
                 URL to the authorization endpoint.
                 400 bad request.
        """
        if path == "sp_metadata":
            start_response('200 OK', [('Content-Type', "text/xml")])
            return self.sp_metadata

        if self.SPHANDLERSSOCACHE not in session or session[self.SPHANDLERSSOCACHE] is None:
            session[self.SPHANDLERSSOCACHE] = Cache()
        if re.search(self.sp_conf.SPVERIFYBASE, path) or re.search(self.sp_conf.SPVERIFYBASEIDP, path):
            if self.sp_conf.SPVERIFYBASE == path:
                session[self.SPHANDLERVERIFYTYPE] = "OP"
            else:
                session[self.SPHANDLERVERIFYTYPE] = "IDP"
            _sso = SSO(self.sp, environ, start_response, self.logger, session[self.SPHANDLERSSOCACHE], **self.args)
            return _sso.do(self.sp_authentication.sp_certificate(environ),
                           self.sp_authentication.sp_encrypt_certificate(environ))
        for regex in self.sp_conf.ASCVERIFYPOSTLIST:
            match = re.search(regex, path)
            if match is not None:
                acs = ACS(self.sp, self.authnmethod, environ, start_response, self.logger,
                          session[self.SPHANDLERSSOCACHE])
                if session[self.SPHANDLERVERIFYTYPE] == "OP":
                    resp = self.handle_response_to_op_handler(acs.post(), environ["HTTP_COOKIE"], session)
                else:
                    if self.sp_conf.COPY_ASSERTION:
                        try:

                            kwargs = {
                                "outstanding_queries": session[self.SPHANDLERSSOCACHE].outstanding_queries,
                                "allow_unsolicited": self.sp.allow_unsolicited,
                                "want_assertions_signed": False,
                                "want_response_signed": self.sp.want_response_signed,
                                "return_addrs": self.sp.service_urls(),
                                "entity_id": self.sp.config.entityid,
                                "attribute_converters": self.sp.config.attribute_converters,
                                "allow_unknown_attributes": self.sp.config.allow_unknown_attributes,
                            }
                            authn_response = AuthnResponse(self.sp.sec, **kwargs)

                            _dict = HttpHandler.query_dictionary(environ)
                            saml_response = _dict["SAMLResponse"]

                            if isinstance(saml_response, list):
                                saml_response = saml_response[0]
                            xmlstr = self.sp.unravel(saml_response, BINDING_HTTP_POST, AuthnResponse.msgtype)

                            authn_response.loads(xmlstr, False)

                            namespace_dict = {}
                            response_search = xmlstr.split(">")
                            for item_resp in response_search:
                                if item_resp.find(":Response") >= 0:
                                    str_split = item_resp.split(" ")
                                    for item in str_split:
                                        if item.find("xmlns:") >= 0:
                                            try:
                                                tmp_namespace = item.split("=")
                                                namespace_dict[tmp_namespace[0].split(":")[1]] = \
                                                    (tmp_namespace[1], item)
                                            except Exception:
                                                pass
                                    break


                            split_name = "EncryptedAssertion"
                            if xmlstr.find(split_name) < 0:
                                split_name = "Assertion"
                            xmlstr_list = xmlstr.split(split_name)

                            start_index = (xmlstr_list[0][::-1].find("<") + 1) * -1
                            str_assertion = xmlstr_list[0][start_index:] + split_name + xmlstr_list[
                                1] + split_name + ">"

                            str_encrypted_assertion = None
                            if split_name == "EncryptedAssertion":
                                str_encrypted_assertion = str_assertion
                                str_assertion = None

                            """
                            authn_response = authn_response.loads(xmlstr, False)
                            assertion = authn_response.response.assertion[0]
                            if len(authn_response.response.encrypted_assertion) == 1:
                                assertion = authn_response.response.encrypted_assertion[0]

                            str_assertion = str(assertion)
                            """

                            uid = hashlib.sha256(Random.new().read(24)).hexdigest()
                            sp_handler_cache = self.get_sp_handler_cache(uid)
                            if sp_handler_cache is None:
                                sp_handler_cache = SpHandlerCache()
                            sp_handler_cache.uid = uid
                            sp_handler_cache.timeout = authn_response.not_on_or_after
                            sp_handler_cache.attributes = {
                                'eduPersonPrincipalName': [hashlib.sha256(Random.new().read(24)).hexdigest()]
                            }
                            sp_handler_cache.assertion = str_assertion
                            sp_handler_cache.encrypted_assertion = str_encrypted_assertion
                            sp_handler_cache.authnresponse = xmlstr
                            sp_handler_cache.namespace_dict = namespace_dict

                            sp_handler_cache.auth = True
                            self.set_sp_handler_cache(uid, sp_handler_cache)

                            session[SpHandler.SPHANDLERFORUID] = uid
                            resp = self.sp_authentication.authn_redirect(environ)
                            return resp(environ, start_response)
                            #resp = self.sp._parse_response(_dict["SAMLResponse"], AuthnResponse,
                            #   "assertion_consumer_service",BINDING_HTTP_POST, **kwargs)
                        except Exception, exc:
                            logger.info("%s" % exc)
                            raise
                    else:
                        resp = self.handle_response_to_idp_handler(acs.post(), environ["HTTP_COOKIE"], session, environ)
                return resp(environ, start_response)
        for regex in self.sp_conf.ASCVERIFYREDIRECTLIST:
            match = re.search(regex, path)
            if match is not None:
                acs = ACS(self.sp, self.authnmethod, environ, start_response, self.logger,
                          session[self.SPHANDLERSSOCACHE])
                resp = self.handle_idp_response(acs.redirect(), environ["HTTP_COOKIE"], session)
                return resp(environ, start_response)


#This class handles user authentication with SAML for the op server.
#This is the standard way to add authentication modules to the provider (oic.oic.provider.Provider)
# in the project pyoidc.
class SPAuthnMethodHandler(UserAuthnMethod):
    #Parameter name for queries to be sent back on the URL, after successful authentication.
    CONST_QUERY = "query"
    #The name for the SP cookie, containing the query parameters for the clients authentication request.
    CONST_SP_COOKIE = "spcookie"

    def __init__(self, srv, redirect_url, return_to):
        """
        Constructor for the class.
        :param srv: Provider for the oic server. If None then it is set by the baseclass. (oic.oic.provider.Provider)
        :param redirect_url: URL that matches the method in the SpHandler class that performs authentication against
                             an IdP.
        :param return_to: The URL to return to after a successful authentication. Generally the OP servers
                          authorization endpoint.
        """
        UserAuthnMethod.__init__(self, srv)
        self.redirect_url = redirect_url
        self.return_to = return_to

    def authn_redirect(self, uid, cookie):
        """
        Creates the URL the SP should redirect to after a successful authentication.
        This is generally the clients request to the authorization endpoint at the OP.
        :param uid: Unique user identification a.k.a sub.
        :param cookie: Cookie string sent from the server. Same as environ["HTTP-COOKIE"]
        :return: A redirect URL.
        """
        return_to = self.generateReturnUrl(self.return_to, uid)
        #Retrieve the query parameters saved by the method __call__ below.
        sp_cookie, _ts, _typ = self.getCookieValue(cookie, self.CONST_SP_COOKIE)
        data = json.loads(sp_cookie)
        if '?' in return_to:
            return_to += "&"
        else:
            return_to += "?"
        return_to += base64.b64decode(data[self.CONST_QUERY])
        #Creates the cookie that the op server needs for authentication.
        return Redirect(return_to, headers=[self.create_cookie(uid, "spm")])

    def __call__(self, query, *args, **kwargs):
        """
        Saves the query parameters sent from the client in a cookie and then redirects to the SPHandler.
        :param query: Query parameters to be returned to op server.
        :param args: Not used.
        :param kwargs: Not used.
        :return:
        """
        cookie = self.create_cookie('{"' + self.CONST_QUERY + '": "' + base64.b64encode(query) + '"}',
                                    self.CONST_SP_COOKIE, self.CONST_SP_COOKIE)
        return Redirect(self.redirect_url, headers=[cookie])

    def verify(self, request, cookie, **kwargs):
        """
        NOT ALLOWED! You should never execute this code.
        Usually verifies the authentication.
        This is not used since the SpHandler class handles the verification and returns the result.
        :param request: Not used.
        :param cookie: Not used.
        :param kwargs: Not used.
        :return:
        """
        logger.fatal('Method verify in SPAuthnMethodHandler should never be called.', exc_info=True)
        return Unauthorized("You are not authorized!")


#Returns user information gathered from an IdP with the SpHandler class.
#This is the standard way to add user information modules to the provider (oic.oic.provider.Provider)
# in the project pyoidc.
class UserInfoSpHandler(object):
    def __init__(self, oic2samlmap, sphandler):
        """
        Constructor.
        :param oic2samlmap: Maps attributes returned from a Saml2 Idp to open id connect.
                            See example in pyOpSamlProxy.client.sp.conf.OPENID2SAMLMAP
                            Dictionary with OpenId name as key and Saml name as value.
        :param sphandler: The SpHandler class object.
        """
        self.oic2samlmap = oic2samlmap
        self.sphandler = sphandler
        #Must be set before the user information endpoint is called on the provider (oic.oic.provider.Provider).
        #If the value is true, then the keys and values sent from the Idp will be returned by the Op as well.
        #If the value is false, then a mapping from Saml to OpenId will be performed as defined in the oic2samlmap.
        self.samlresponse = False

    def set_samlresponse(self, samlresponse):
        """
        If samlresponse is true, then the keys and values sent from the Idp will be returned by the Op as well.
        If samlresponse is false, then a mapping from Saml to OpenId will be performed as defined in the oic2samlmap.
        :param samlresponse: See above.
        """
        self.samlresponse = samlresponse

    def verify_information(self, environ, session):
        """
        Verifies if the attributes collected by the SpHandler is valid or if an timeout have occurred.
        If a timeout occurs then the client have to reauthenticate to get new data.
        This method must be called explicitly by the Op handler.
        :param environ: WSGI enviroment.
        :param session: Current session. (pyOpSamlProxy.util.session.Session)
        :return:
        """
        sub = self.sphandler.get_sub(environ, session)
        sp_handler_cache = self.sphandler.get_sp_handler_cache(sub)
        if sp_handler_cache is not None:
            if sp_handler_cache.auth:
                if SpHandler.verify_timeout(sp_handler_cache.timeout) or sp_handler_cache.attributes is None:
                    logger.info('Attributes collected from the IdP is not valid.', exc_info=True)
                    return Unauthorized("You are not authorized!")
        return True

    def __call__(self, userid, user_info_claims=None, **kwargs):
        """
        Returns the user information for a user authenticated with the SpHandler.
        All Saml2 attributes are cached and must still be valid.
        The Saml2 attributes a mapped to oic profile.
        :param userid: Unique identifier for the user.
        :param user_info_claims: Oic claims for user info. A dictionary with all OpenId attributes to returned as key.
        :param kwargs: Not used.
        :return: User information as a key value dictionary.
        """
        sp_handler_cache = self.sphandler.get_sp_handler_cache(userid)
        if self.samlresponse:
            return sp_handler_cache.attributes
        userinfo = {}
        if sp_handler_cache is not None and sp_handler_cache.attributes is not None and not SpHandler.verify_timeout(
                sp_handler_cache.timeout):
            for oic, saml in self.oic2samlmap.items():
                if saml in sp_handler_cache.attributes:
                    userinfo[oic] = sp_handler_cache.attributes[saml]
        if "sub" not in userinfo:
            userinfo["sub"] = userid

        if user_info_claims is None:
            return userinfo
        else:
            result = {}
            for key, restr in user_info_claims.items():
                try:
                    result[key] = userinfo[key]
                except KeyError:
                    pass
            return result

