import urllib

__author__ = 'haho0032'
import logging
from saml2.httputil import Redirect, Unauthorized
from dirg_util.http_util import HttpHandler
from dirg_util.session import Session
from idproxy.provider.idp.auth.util import IdPAuthentication

logger = logging.getLogger("pyOpSamlProxy.provider.idp.auth.sp")


class MultipleAuthentication(IdPAuthentication):
    MULTIPLEAUTHENTICATIONREDIRECT = "MULTIPLEAUTHENTICATIONREDIRECT"
    MUTLIPLEAUTHENTICATIONCOUNTER = "MUTLIPLEAUTHENTICATIONCOUNTER"

    def __init__(self, idphandler, auth_list, user_info=None):
        IdPAuthentication.__init__(self, idphandler)
        self.auth_list = auth_list
        self.auth_list_lengt = len(auth_list)
        self._user_info = user_info

    def authenticate(self, environ, start_response, reference, key, redirect_uri, **kwargs):
        session = Session(environ)
        params = HttpHandler.query_dictionary(environ)
        paramstr = None
        for tmpkey, value in params.items():
            tmpparamstr = None
            if type(value) is list:
                for v in value:
                    if tmpparamstr is None:
                        tmpparamstr = ""
                    else:
                        tmpparamstr += "&"
                    tmpparamstr = urllib.urlencode({tmpkey: v})
            else:
                tmpparamstr = urllib.urlencode({tmpkey: value})
            if paramstr is None:
                paramstr = "?"
            else:
                paramstr += "&"
            paramstr += tmpparamstr
        if self.MUTLIPLEAUTHENTICATIONCOUNTER not in session or session[self.MUTLIPLEAUTHENTICATIONCOUNTER] is None:
            session[self.MUTLIPLEAUTHENTICATIONCOUNTER] = 0
        authn_method = session[self.MUTLIPLEAUTHENTICATIONCOUNTER]
        #query = Test how the url should be built up. The user should be redirected to this url as long
        #as all method is not tested.
        query = environ['PATH_INFO'] + paramstr
        session[self.MULTIPLEAUTHENTICATIONREDIRECT] = query
        if self.auth_list_lengt <= 0:
            resp = Unauthorized("No authentication method")
            return resp(environ, start_response)
        else:
            return self.auth_list[authn_method].authenticate(environ, start_response, reference, key, redirect_uri)

    def verify(self, environ, start_response):
        session = Session(environ)
        if self.MUTLIPLEAUTHENTICATIONCOUNTER in session:
            authn_method = session[self.MUTLIPLEAUTHENTICATIONCOUNTER]
            if authn_method > (self.auth_list_lengt - 1) or self.auth_list_lengt == 0:
                resp = Unauthorized("No authentication method")
            elif authn_method == (self.auth_list_lengt - 1):
                return self.auth_list[authn_method].verify(environ, start_response)
            else:
                _ok = self.auth_list[authn_method].verify_bool(environ, start_response)
                if _ok:
                    session[self.MUTLIPLEAUTHENTICATIONCOUNTER] = authn_method + 1
                    resp = Redirect(session[self.MULTIPLEAUTHENTICATIONREDIRECT])
                else:
                    return self.auth_list[authn_method].verify(environ, start_response)
        else:
            resp = Unauthorized("No authentication method")
        return resp(environ, start_response)

    def information(self, environ, start_response, uid):
        #Well we do not really have any solution setup yet.
        #Have to build a custom information collector as well. They are harcoded. NOT OK
        #Here is a good place for common used module for information retrieval.
        #Could even perform aggregation for each service that is validated.
        #Collect information from each performed authentication.
        #Collect information from all AA's and consiludate the information. A good way could be to
        #back list of information if the same attributes contains multiple values.
        #It will be up to the sp to sort out the information.
        #Or even setup the endpoints as some kind of key.
        session = Session(environ)
        if self.MUTLIPLEAUTHENTICATIONCOUNTER in session:
            if self._user_info is None:
                authn_method = session[self.MUTLIPLEAUTHENTICATIONCOUNTER]
                return self.auth_list[authn_method].information(environ, start_response, uid)
            else:
                return self._user_info.information(environ, start_response, uid)
        return {}

    def extra(self, environ, start_response, uid):
        session = Session(environ)
        if self.MUTLIPLEAUTHENTICATIONCOUNTER in session:
            if self._user_info is None:
                authn_method = session[self.MUTLIPLEAUTHENTICATIONCOUNTER]
                return self.auth_list[authn_method].extra(environ, start_response, uid)
            else:
                return self._user_info.extra(environ, start_response, uid)
        return {}