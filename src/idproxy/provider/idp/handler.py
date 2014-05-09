import importlib

from saml2.httputil import Unauthorized
from saml2.metadata import create_metadata_string
from dirg_util.http_util import HttpHandler

from idproxy.provider.idp.auth.cas import CasAuth
from idproxy.provider.idp.auth.multiple import MultipleAuthentication
from idproxy.provider.idp.auth.password import PasswordYubikeyAuth
from idproxy.provider.idp.auth.sp import SpAuthentication
from idproxy.provider.idp.auth.unspecified import UnspecifiedAuth


__author__ = 'haho0032'
import re
import base64
import time
import logging
from Cookie import SimpleCookie
from saml2 import server
from saml2 import time_util
from saml2.authn_context import AuthnBroker
from saml2.authn_context import UNSPECIFIED
from saml2.authn_context import authn_context_class_ref
from idproxy.provider.idp.util import Cache
from idproxy.provider.idp.util import SSO
from idproxy.provider.idp.util import SLO
from idproxy.provider.idp.util import AIDR
from idproxy.provider.idp.util import ARS
from idproxy.provider.idp.util import NMI
from idproxy.provider.idp.util import NIM
from idproxy.provider.idp.util import AQS
from idproxy.provider.idp.util import ATTR
from idproxy.provider.idp.util import AuthCookie


#Add a logger for this class.
logger = logging.getLogger("pyOpSamlProxy.provider.idp.util")


#This class is responsible for wrapping a pysaml2 IdP implementation.
class IdPHandler(object):
    AUTHORIZATION_MULTIPLEAUTHN = "MULTIPLEAUTHN"
    #See idp_confy.py. Name of Saml authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_SAML = "SAML"
    #See idp_confy.py. Name of CAS authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_CAS = "CAS"
    #See idp_confy.py in the AUTHORIZATION dictionary. User information should be collected with SAML.
    USER_INFO_SAML = "SAML"
    #See idp_confy.py in the AUTHORIZATION dictionary. User information should be collected with LDAP.
    USER_INFO_LDAP = "LDAP"
    #See idp_confy.py in the AUTHORIZATION dictionary. User information should be collected with local dictionary.
    USER_INFO_SIMPLE = "SIMPLE"
    #See idp_confy.py. Name of PASSWORD authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_PASSWORD = "PASSWORD"
    #See idp_confy.py. Name of YUBIKEY authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_YUBIKEY = "YUBIKEY"
    #See idp_confy.py. Name of PASSWORD authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_PASSWORD_YUBIKEY = "PASSWORD_YUBIKEY"
    #See idp_confy.py in the AUTHORIZATION dictionary.
    # The key contains the acr_value for a specific authorization method.
    AUTHORIZATION_ACR = "ACR"
    #See idp_confy.py in the AUTHORIZATION dictionary. The key contains the weight for a specific authorization method.
    AUTHORIZATION_WEIGHT = "WEIGHT"
    #See idp_confy.py in the AUTHORIZATION dictionary.
    # The key contains the URL that is responsible for specific authorization method.
    AUTHORIZATION_URL = "URL"
    #See idp_confy.py in the AUTHORIZATION dictionary.
    #The key contains type of user information module to use for a specific authorization method.
    AUTHORIZATION_USER_INFO = "USER_INFO"
    #See idp_confy.py in the AUTHORIZATION dictionary.
    #The key that contains an ordered list of authentication methods.
    AUTHENTICATION_AUTHNLIST = "AUTHNLIST"
    #The dictionary that contains the authorization configuration.
    IDP_VERIFY_URL = "idpverify"
    AUTHN_REFERENCE = "authn_reference"
    # map urls to functions
    AUTHN_URLS = [
        # sso
        (r'sso/post$', (SSO, "post")),
        (r'sso/post/(.*)$', (SSO, "post")),
        (r'sso/redirect$', (SSO, "redirect")),
        (r'sso/redirect/(.*)$', (SSO, "redirect")),
        (r'sso/art$', (SSO, "artifact")),
        (r'sso/art/(.*)$', (SSO, "artifact")),
        # slo
        (r'slo/redirect$', (SLO, "redirect")),
        (r'slo/redirect/(.*)$', (SLO, "redirect")),
        (r'slo/post$', (SLO, "post")),
        (r'slo/post/(.*)$', (SLO, "post")),
        (r'slo/soap$', (SLO, "soap")),
        (r'slo/soap/(.*)$', (SLO, "soap")),
        #
        (r'airs$', (AIDR, "uri")),
        (r'ars$', (ARS, "soap")),
        # mni
        (r'mni/post$', (NMI, "post")),
        (r'mni/post/(.*)$', (NMI, "post")),
        (r'mni/redirect$', (NMI, "redirect")),
        (r'mni/redirect/(.*)$', (NMI, "redirect")),
        (r'mni/art$', (NMI, "artifact")),
        (r'mni/art/(.*)$', (NMI, "artifact")),
        (r'mni/soap$', (NMI, "soap")),
        (r'mni/soap/(.*)$', (NMI, "soap")),
        # nim
        (r'nim$', (NIM, "soap")),
        (r'nim/(.*)$', (NIM, "soap")),
        #
        (r'aqs$', (AQS, "soap")),
        (r'attr$', (ATTR, "soap"))
    ]

    IDP_AUTH_COOKIE_NAME = "idpauthnproxy"

    def __init__(self, args, template_lookup, sphandler, ISSUER):
        idpconfig = importlib.import_module(args.idpconfig)
        self.copy_sp_cert = idpconfig.COPYSPCERT
        self.copy_sp_key = idpconfig.COPYSPKEY
        self.passwd = idpconfig.PASSWD
        self.cas_server = idpconfig.CAS_SERVER
        self.yubikey_db = idpconfig.YUBIKEY_DB
        self.yubikey_server = idpconfig.YUBIKEY_SERVER
        self.service_url = ISSUER + "/" + self.IDP_VERIFY_URL
        self.template_lookup = template_lookup
        self.idp_server = self.setup_saml2_server(args.idpconfig, idpconfig, idpconfig.SYM_KEY)
        self.authn_broker = self.setup_authn_broker(ISSUER, sphandler, idpconfig.AUTHORIZATION)
        self.auth_cookie = None
        self.non_authn_urls = [
            (r'%s?(.*)$' % self.IDP_VERIFY_URL, self.do_verify),
            (r'sso/ecp$', (SSO, "ecp")),
        ]
        self.sphandler = sphandler
        self.idp_metadata = create_metadata_string(args.idpconfig + ".py", self.idp_server.config, args.valid,
                                                   args.cert,
                                                   args.keyfile, args.id_idp, args.name_idp, args.sign)

    def setup_authn_broker(self, base_url, sphandler, authorization):
        ab = AuthnBroker()
        sphandler.sp_authentication = SpAuthentication(self, sphandler)
        cas_auth = CasAuth(self, self.cas_server, self.service_url)
        password_auth = PasswordYubikeyAuth(self, self.passwd, password=True,
                                            yubikey=False)
        yubikey_auth = PasswordYubikeyAuth(self, self.passwd, password=False,
                                           yubikey=True)
        password_yubikey_auth = PasswordYubikeyAuth(self, self.passwd, password=True,
                                                    yubikey=True)
        for authkey, value in authorization.items():
            level = str(value[IdPHandler.AUTHORIZATION_WEIGHT])
            url = value[IdPHandler.AUTHORIZATION_URL]
            acr = value[IdPHandler.AUTHORIZATION_ACR]
            user_info = value[IdPHandler.AUTHORIZATION_USER_INFO]
            if authkey == IdPHandler.AUTHORIZATION_SAML:
                sphandler.sp_authentication.user_info(user_info)
                ab.add(acr, sphandler.sp_authentication, level, url)
            elif authkey == IdPHandler.AUTHORIZATION_CAS:
                cas_auth.user_info(user_info)
                ab.add(acr, cas_auth, level, url)
            elif authkey == IdPHandler.AUTHORIZATION_PASSWORD_YUBIKEY:
                password_yubikey_auth.user_info(user_info)
                ab.add(acr, password_yubikey_auth, level, url)
            elif authkey == IdPHandler.AUTHORIZATION_PASSWORD:
                password_auth.user_info(user_info)
                ab.add(acr, password_auth, level, url)
            elif authkey == IdPHandler.AUTHORIZATION_YUBIKEY:
                yubikey_auth.user_info(user_info)
                ab.add(acr, yubikey_auth, level, url)
            elif authkey == IdPHandler.AUTHORIZATION_MULTIPLEAUTHN:
                authn_list = []
                for m_items in value[IdPHandler.AUTHENTICATION_AUTHNLIST]:
                    m_authkey = m_items[IdPHandler.AUTHORIZATION_ACR]
                    if m_authkey == IdPHandler.AUTHORIZATION_SAML:
                        authn_list.append(sphandler.sp_authentication)
                    elif m_authkey == IdPHandler.AUTHORIZATION_CAS:
                        authn_list.append(cas_auth)
                    elif m_authkey == IdPHandler.AUTHORIZATION_PASSWORD_YUBIKEY:
                        authn_list.append(password_yubikey_auth)
                    elif m_authkey == IdPHandler.AUTHORIZATION_PASSWORD:
                        authn_list.append(password_auth)
                    elif m_authkey == IdPHandler.AUTHORIZATION_YUBIKEY:
                        authn_list.append(yubikey_auth)
                ab.add(acr, MultipleAuthentication(self, authn_list, user_info), level, url)
            else:
                ab.add(authn_context_class_ref(UNSPECIFIED), UnspecifiedAuth(self), level, url)
        return ab

    def setup_saml2_server(self, config, idpconfig, symkey):
        idp = server.Server(config, cache=Cache(idpconfig.CACHE_1, idpconfig.CACHE_2), symkey=symkey)
        idp.ticket = {}
        return idp

    def verify_provider_requests(self, path, environ):
        if path == "idp_metadata":
            return True
        uid = self.uid(environ)
        for regex, callback in self.urlpatterns(uid):
            match = re.search(regex, path)
            if match is not None:
                return True
        return False

    def handle_provider_requests(self, environ, start_response, path):
        if path == "idp_metadata":
            start_response('200 OK', [('Content-Type', "text/xml")])
            return self.idp_metadata
        auth_cookie = self.authorization_cookie(environ)
        uid = None
        if auth_cookie is not None:
            uid = auth_cookie.uid
            self.auth_cookie = auth_cookie
        for regex, callback in self.urlpatterns(uid):
            match = re.search(regex, path)
            if match is not None:
                try:
                    environ['myapp.url_args'] = match.groups()[0]
                except IndexError:
                    environ['myapp.url_args'] = path

                logger.debug("Callback: %s" % (callback,))
                if isinstance(callback, tuple):
                    cls = callback[0](environ, start_response, self, uid)
                    func = getattr(cls, callback[1])
                    return func()
                #Functions like self.do_verify
                return callback(environ, start_response, uid)

    def urlpatterns(self, uid):
        url_patterns = self.AUTHN_URLS
        if not uid:
            url_patterns = self.non_authn_urls + url_patterns
        return url_patterns

    def uid(self, environ):
        auth_cookie = self.authorization_cookie(environ)
        if auth_cookie is not None:
            return auth_cookie.uid
        return None

    def retrieve_cookie(self, environ, name):
        cookie = environ['HTTP_COOKIE']
        if cookie:
            cookie_obj = SimpleCookie(cookie)
            morsel = cookie_obj.get(name, None)
            if morsel:
                try:
                    decoded = base64.b64decode(morsel.value)
                    key = None
                    ref = None
                    try:
                        key, ref = base64.b64decode(morsel.value).split(":")
                    except:
                        if decoded is not None:
                            return decoded
                    return key, ref
                except KeyError:
                    pass
            else:
                logger.debug("No cookie with the name " + name)
        return None

    def authorization_cookie(self, environ):
        try:
            cookie = self.retrieve_cookie(environ, self.IDP_AUTH_COOKIE_NAME)
            if cookie is not None:
                auth_cookie = AuthCookie(self.idp_server.cache.uid2user[cookie[0]], cookie[1])
                return auth_cookie
        except KeyError:
            return AuthCookie()
        return None

    def set_authorization_cookie(self, uid, authn_ref):
        return self.set_cookie(self.IDP_AUTH_COOKIE_NAME, "/", uid, authn_ref)

    def set_cookie(self, name, _, *args):
        cookie = SimpleCookie()
        cookie[name] = base64.b64encode(":".join(args))
        cookie[name]['path'] = "/"
        cookie[name]["expires"] = self._expiration(5)  # 5 minutes from now
        logger.debug("Cookie expires: %s" % cookie[name]["expires"])
        return tuple(cookie.output().split(": ", 1))

    def delete_authorization_cookie(self, environ):
        return self.delete_cookie(environ, self.IDP_AUTH_COOKIE_NAME)

    def delete_cookie(self, environ, name):
        cookie = environ.get("HTTP_COOKIE", '')
        logger.debug("delete KAKA: %s" % cookie)
        if cookie:
            cookie_obj = SimpleCookie(cookie)
            morsel = cookie_obj.get(name, None)
            cookie = SimpleCookie()
            cookie[name] = ""
            cookie[name]['path'] = "/"
            logger.debug("Expire: %s" % morsel)
            cookie[name]["expires"] = self._expiration("dawn")
            return tuple(cookie.output().split(": ", 1))
        return None

    def _expiration(self, timeout, tformat="%a, %d-%b-%Y %H:%M:%S GMT"):
        if timeout == "now":
            return time_util.instant(tformat)
        elif timeout == "dawn":
            return time.strftime(tformat, time.gmtime(0))
        else:
            # validity time should match lifetime of assertions
            return time_util.in_a_while(minutes=timeout, format=tformat)

    def do_verify(self, environ, start_response, _):
        query = HttpHandler.query_dictionary(environ)
        authn_ref = self.authn_broker.pick()[0][0].get_authn_reference(query)
        if authn_ref is not None:
            authn = self.authn_broker[authn_ref]
            if authn:
                return authn["method"].verify(environ, start_response)

        resp = Unauthorized("")
        return resp(environ, start_response)

