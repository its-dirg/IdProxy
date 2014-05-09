import urllib

__author__ = 'haho0032'
import logging
from saml2.httputil import Redirect, Unauthorized
from idproxy.client.sp.handler import SpHandler
from dirg_util.http_util import HttpHandler
from dirg_util.session import Session
from idproxy.provider.idp.auth.util import IdPAuthentication


logger = logging.getLogger("pyOpSamlProxy.provider.idp.auth.sp")


class SpAuthentication(IdPAuthentication):
    SPAUTHENTICATIONCOOKIE = "SPAUTHENTICATIONCOOKIE"

    def __init__(self, idphandler, sphandler):
        IdPAuthentication.__init__(self, idphandler)
        self.sphandler = sphandler
        self._user_info = None

    def sp_auth_cookie(self, environ):
        cookie_load = self.idphandler.retrieve_cookie(environ, self.SPAUTHENTICATIONCOOKIE)
        cookie_dict = self.decrypt_dict(cookie_load)
        return cookie_dict

    def sp_certificate(self, environ):
        cookie_dict = self.sp_auth_cookie(environ)
        if "sid" in cookie_dict and cookie_dict["sid"] is not None and len(cookie_dict["sid"]) > 0:
            return self.sphandler.certificate_from_cache(cookie_dict["sid"])
        return None

    def sp_encrypt_certificate(self, environ):
        cookie_dict = self.sp_auth_cookie(environ)
        if "encrypt_sid" in cookie_dict and cookie_dict["encrypt_sid"] is not None and len(cookie_dict["encrypt_sid"]) > 0:
            return self.sphandler.certificate_from_cache(cookie_dict["encrypt_sid"])
        return None

    def authn_redirect(self, environ):
        cookie_dict = self.sp_auth_cookie(environ)
        return Redirect(cookie_dict["query"])

    def authenticate(self, environ, start_response, reference, key, redirect_uri, **kwargs):
        _sid = ""
        _encrypt_sid = ""
        if "certificate_str" in kwargs and kwargs["certificate_str"] is not None:
            _sid = self.sphandler.add_certificate_to_cache(kwargs["certificate_str"])
        if "certificate_key_str" in kwargs and kwargs["certificate_key_str"] is not None:
            _encrypt_sid = self.sphandler.add_certificate_to_cache(kwargs["certificate_key_str"])

        query_dict = {
            "key": key,
            "authn_reference": reference,
            "redirect_uri": redirect_uri
        }
        f = {'query': self.encrypt_dict(query_dict)}
        urllib.urlencode(f)

        query = "/" + self.idphandler.IDP_VERIFY_URL + "?" + urllib.urlencode(f)

        cookie_load = {
            "query": query,
            "sid": _sid,
            "encrypt_sid": _encrypt_sid
        }

        cookie_load = self.encrypt_dict(cookie_load)

        cookie = self.idphandler.set_cookie(self.SPAUTHENTICATIONCOOKIE, "/", cookie_load)
        resp = Redirect("/" + self.sphandler.sp_conf.SPVERIFYBASEIDP, headers=[cookie])

        return resp(environ, start_response)

    def verify_bool(self, environ, start_response):
        session = Session(environ)
        user = session[SpHandler.SPHANDLERFORUID]

        query = HttpHandler.query_dictionary(environ)
        logger.debug("do_verify: %s" % query)

        sp_handler_cache = self.sphandler.get_sp_handler_cache(user)

        if sp_handler_cache is None or not sp_handler_cache.auth or sp_handler_cache.uid is None:
            return False
        return True

    def verify(self, environ, start_response):
        _ok = self.verify_bool(environ, start_response)
        if not _ok:
            resp = Unauthorized("Unknown user or wrong password")
        else:
            session = Session(environ)
            user = session[SpHandler.SPHANDLERFORUID]
            query = HttpHandler.query_dictionary(environ)
            query = self.decrypt_dict(query["query"])
            resp = self.setup_idp(user, query["authn_reference"], query["redirect_uri"], query["key"])
        return resp(environ, start_response)

    def user_info(self, user_info):
        self._user_info = user_info

    def information(self, environ, start_response, uid):
        if self._user_info is None:
            session = Session(environ)
            user = session[SpHandler.SPHANDLERFORUID]
            sp_handler_cache = self.sphandler.get_sp_handler_cache(user)
            return sp_handler_cache.attributes
        return self._user_info.information(environ, start_response, uid)

    def sp_handler_cache(self, environ, start_response, uid):
        session = Session(environ)
        user = session[SpHandler.SPHANDLERFORUID]
        sp_handler_cache = self.sphandler.get_sp_handler_cache(user)
        return sp_handler_cache\

    def extra(self, environ, start_response, uid):
        if self._user_info is None:
            return {}
        return self._user_info.extra(environ, start_response, uid)
