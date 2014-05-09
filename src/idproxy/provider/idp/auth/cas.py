import urllib
from urlparse import parse_qs

from auth.cas import CasAuthentication


__author__ = 'haho0032'
import logging
from saml2.httputil import Unauthorized
from idproxy.provider.idp.auth.util import IdPAuthentication
from dirg_util.http_util import HttpHandler

logger = logging.getLogger("pyOpSamlProxy.provider.idp.util")


class CasAuth(IdPAuthentication):
    def __init__(self, idphandler, cas_server, service_url, extra_validation=None):
        IdPAuthentication.__init__(self, idphandler)
        self._user_info = None
        self.auth_helper = CasAuthentication(cas_server, service_url, extra_validation,
                                             cookie_dict=None, cookie_object=idphandler.idp_server)

    def user_info(self, user_info):
        self._user_info = user_info

    def information(self, environ, start_response, uid):
        if self._user_info is None:
            return None
        return self._user_info.information(environ, start_response, uid)

    def extra(self, environ, start_response, uid):
        if self._user_info is None:
            return None
        return self._user_info.extra(environ, start_response, uid)

    def authenticate(self, environ, start_response, reference, key, redirect_uri, **kwargs):
        logger.info("The login page")
        headers = []

        query_dict = {
            self.AUTHN_REFERENCE_PARAM: reference,
        }

        query = {
            "key": key,
            #This is sent encrypted to the CAS server so we can pick the correct authn when we return to the proxy.
            self.QUERY_PARAM: self.encrypt_dict(query_dict),
            self.AUTHN_REFERENCE_PARAM: reference,
            "redirect_uri": redirect_uri
        }

        _filter = [
            self.QUERY_PARAM
        ]

        resp = self.auth_helper.create_redirect(urllib.urlencode(query), _filter)
        return resp(environ, start_response)

    def verify_bool(self, environ, start_response):
        query = HttpHandler.query_dictionary(environ)
        cookie = environ.get('HTTP_COOKIE')
        valid = False
        try:
            valid, uid, return_to_query = self.auth_helper.verify(query, cookie)
        except (AssertionError, KeyError):
            return valid
        return valid

    def verify(self, environ, start_response):
        request = HttpHandler.query_dictionary(environ)
        cookie = environ.get('HTTP_COOKIE')
        user = None
        valid = False
        query = {}
        try:
            valid, user, return_to_query = self.auth_helper.verify(request, cookie)
            query = dict((k, v if len(v) > 1 else v[0]) for k, v in parse_qs(return_to_query).iteritems())
        except KeyError:
            pass
        if not valid:
            resp = Unauthorized("Unknown user or wrong password")
        else:
            if len(query) != 3 and "authn_reference" not in query or "redirect_uri" not in query or "key" not in query:
                resp = Unauthorized("Unknown user or wrong password")
            else:
                resp = self.setup_idp(user, query["authn_reference"], query["redirect_uri"], query["key"])
        return resp(environ, start_response)

