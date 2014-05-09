from auth.form import DirgUsernamePasswordYubikeyMako

__author__ = 'haho0032'
import logging
from saml2.httputil import Unauthorized
from idproxy.provider.idp.auth.util import IdPAuthentication
from dirg_util.http_util import HttpHandler

logger = logging.getLogger("pyOpSamlProxy.provider.idp.util")


class PasswordYubikeyAuth(IdPAuthentication):
    def __init__(self, idphandler, passwd, password=True, yubikey=False):
        IdPAuthentication.__init__(self, idphandler)
        self.passwd = passwd
        self._user_info = None
        yubikey_db = None
        yubikey_server = None
        yubikey_otp_parameter = None
        mako_file = "idplogin_password.mako"
        password_parameter = None
        if password:
            password_parameter = "password"
        if yubikey:
            yubikey_db = idphandler.yubikey_db
            yubikey_server = idphandler.yubikey_server
            yubikey_otp_parameter = "otp"
            #mako_file = "yubikeylogin.mako"
            mako_file = "idplogin_yubikey.mako"
        if yubikey and password:
            mako_file = "idplogin_password_yubikey.mako"

        self.auth_helper = DirgUsernamePasswordYubikeyMako("login", mako_file, self.idphandler.template_lookup,
                                                           passwd, password_parameter, yubikey_db, yubikey_server,
                                                           yubikey_otp_parameter)

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
        query = {
            "key": key,
            self.AUTHN_REFERENCE_PARAM: reference,
            "redirect_uri": redirect_uri
        }
        argv = {
            "action": "/" + self.idphandler.IDP_VERIFY_URL,
            "login": "",
            "password": "",
            "otp": "",
            self.QUERY_PARAM: self.encrypt_dict(query)
        }
        logger.info("do_authentication argv: %s" % argv)
        resp = self.auth_helper.create_response(argv)
        return resp(environ, start_response)

    def verify_bool(self, environ, start_response):
        query = HttpHandler.query_dictionary(environ)
        valid = False
        try:
            valid, uid, parameters = self.auth_helper.verify(query)
        except (AssertionError, KeyError):
            return valid

        return valid

    def verify(self, environ, start_response):
        request = HttpHandler.query_dictionary(environ)
        user = None
        valid = False
        query = {}
        try:
            valid, user, parameters = self.auth_helper.verify(request)
            query = self.decrypt_dict(parameters[self.QUERY_PARAM])
        except KeyError:
            pass
        if not valid:
            resp = Unauthorized("Unknown user or wrong password")
        else:
            if len(query) != 3 and self.AUTHN_REFERENCE_PARAM not in query or "redirect_uri" not in query or \
               "key" not in query:
                resp = Unauthorized("Unknown user or wrong password")
            else:
                resp = self.setup_idp(user, query[self.AUTHN_REFERENCE_PARAM], query["redirect_uri"], query["key"])
        return resp(environ, start_response)

