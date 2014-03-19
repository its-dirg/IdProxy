from idproxy import ServiceErrorException

__author__ = 'haho0032'
import urlparse
import uuid
import shelve
import re
import traceback
import sys
from urlparse import parse_qs

from oic.utils import http_util
from oic.utils.http_util import wsgi_wrapper
from oic.utils.sdb import SessionDB
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.client import verify_client
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authz import AuthzHandling
from oic.oic.provider import Provider
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.oic.provider import RegistrationEndpoint
from oic.oic.provider import EndSessionEndpoint
from oic.utils.keyio import KeyBundle, dump_jwks
from oic.utils.webfinger import WebFinger, OIC_ISSUER
from oic.utils.userinfo import UserInfo
from oic.utils.authn.user_cas import CasAuthnMethod
from oic.utils.authn.ldap_member import UserLDAPMemberValidation
from dirg_util.http_util import HttpHandler

from idproxy.client.sp.handler import UserInfoSpHandler
from idproxy.provider.op.util import UserInfoAuthHandler, MultipleAuthHandler


#A session connected cache that holds information for each user.
class OpHandlerCache:
    def __init__(self):
        #Contains the last acr_value sent by the client.
        #See op_confy.py. Can be the ACR value string in the dictionary AUTHORIZATION.
        self.auth = None


#This class represents an OP and is written for a WSGI application.
#If configured togheter with pyOpSamlProxy.client.sp.handler this OP can act as a proxy against an IdP.
#Use the method verify_provider_requests to check if the OpHandler should handle the request.
#Use the method handle_provider_requests to handle the request.
class OpHandler:
    #Constant that is used to define the value when a chain of authentication methods is used.
    AUTHORIZATION_MULTIPLEAUTHN = "MULTIPLEAUTHN"
    #See op_confy.py. Name of Saml authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_SAML = "SAML"
    #See op_confy.py. Name of CAS authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_CAS = "CAS"
    #See op_confy.py in the AUTHORIZATION dictionary. User information should be collected with SAML.
    USER_INFO_SAML = "SAML"
    #See op_confy.py in the AUTHORIZATION dictionary. User information should be collected with LDAP.
    USER_INFO_LDAP = "LDAP"
    #See op_confy.py in the AUTHORIZATION dictionary. User information should be collected with local dictionary.
    USER_INFO_SIMPLE = "SIMPLE"
    #See op_confy.py. Name of PASSWORD authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_PASSWORD = "PASSWORD"
    #See op_confy.py. Name of YUBIKEY authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_YUBIKEY = "YUBIKEY"
    #See op_confy.py. Name of PASSWORD authorization in the AUTHORIZATION dictionary.
    AUTHORIZATION_PASSWORD_YUBIKEY = "PASSWORD_YUBIKEY"
    #See op_confy.py in the AUTHORIZATION dictionary.
    # The key contains the acr_value for a specific authorization method.
    AUTHORIZATION_ACR = "ACR"
    #See op_confy.py in the AUTHORIZATION dictionary. The key contains the weight for a specific authorization method.
    AUTHORIZATION_WEIGHT = "WEIGHT"
    #See op_confy.py in the AUTHORIZATION dictionary.
    # The key contains the URL that is responsible for specific authorization method.
    AUTHORIZATION_URL = "URL"
    #See op_confy.py in the AUTHORIZATION dictionary.
    #The key contains type of user information module to use for a specific authorization method.
    AUTHORIZATION_USER_INFO = "USER_INFO"
    #The dictionary that contains the authorization configuration.
    AUTHENTICATION = "AUTHENTICATION"
    #See op_confy.py in the AUTHORIZATION dictionary.
    #The key that contains an ordered list of authentication methods.
    AUTHENTICATION_AUTHNLIST = "AUTHNLIST"
    #OpenId standard name for the request parameter that contains requested authentication method by the client.
    ACR_VALUES = "acr_values"
    #Key in the current session for the user. (pyOpSamlProxy.util.session.Session)
    #This key contains True or False. If true should the session be cleaned at the first opportunity.
    CLEARSESSION = "CLEARSESSION"

    def __init__(self, logger, config, mako_lookup, sphandler, test=False, debug=False):
        """
        Constructor.
        Initializes OpHandler with a provider (oic.oic.provider.Provider).
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
        :param logger: A logger.
        :param config: Configuration file. (op_conf.py)
        :param mako_lookup: A mako template lookup. (mako.lookup.TemplateLookup)
        :param test: True if application is running as test.
        :param debug: True if the application is running in debug mode.
        """
        self.logger = logger
        self.authorization_url = "%s/authorization" % config.ISSUER
        self.mako_lookup = mako_lookup
        self.sphandler = sphandler
        self.test = test
        self.debug = debug
        self.seed = uuid.uuid4().get_urn()
        #Keeps track of active beaker sessions and if they are invalid.
        self.session_cache = config.OP_CACHE_2
        #URL's handled match with methods to handle them.
        #TODO verify if verifyClientId should remain. Not following standard.
        #verifyClientId can be used to verify the clients client_id.
        #verify is used to verify a performed authentication.
        #samluserinfo is a new endpoint for the samlproxy, that gives a full saml response.
        #well-known/openid-configuration enpoint to retrieve the Op's configuration.
        #.well-known/webfinger Responds at webfinger requests.
        self.urlmap = [
            (r'^verifyClientId', self.verify_client_id),
            (r'^verify', self.verify),
            (r'^samluserinfo', self.samluserinfo),
            (r'^.well-known/openid-configuration', self.op_info),
            (r'^.well-known/webfinger', self.webfinger),
        ]
        #A map that contains user identification as key and an instance of the class OpHandlerCache as value.
        self.ophandlercache = config.OP_CACHE_2

        #Contians all endpoints (URL's) for the OP server and matches them to a method.
        self.endpoints = [
            AuthorizationEndpoint(self.authorization),
            TokenEndpoint(self.token),
            UserinfoEndpoint(self.userinfo),
            RegistrationEndpoint(self.registration),
            EndSessionEndpoint(self.endsession)
        ]

        #Add all endpoints to the url map.
        for endp in self.endpoints:
            self.urlmap.append(("^%s" % endp.etype, endp))

        #Setup the provider. (oic.oic.provider.Provider)
        self.provider = self.setup_provider(logger, mako_lookup, self.authorization_url, config, self.endpoints,
                                            sphandler, self.seed,
                                            test, debug)

    def setup_provider(self, logger, mako_lookup, authorization_url, config, endpoints, sphandler, seed,
                       test=False, debug=False):
        """
        Initializes a pyoidc provider. (oic.oic.provider.Provider)
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
                          This class is a SAML SP and is used by the OpHandler to acts as a proxy against SAML IdP's.
        :param seed: Cookie seed to make sure that session cookie for the provider is unique for each server instance.
        :param logger: A logger.
        :param mako_lookup: A mako template lookup. (mako.lookup.TemplateLookup)
        :param authorization_url: URL that should handle client authorizations.
        :param config: Configuration file. (op_conf.py)
        :param endpoints: All endpoints that this provider can handle. Dictionary with endpoint url as key and
                          method in this class to handle them as value.
        :param test: True if application is running as test.
        :param debug: True if the application is running in debug mode.
        :return: A provider. (oic.oic.provider.Provider)
        """
        cdb = shelve.open("client_db", writeback=True)

        ac = self.setup_authorization(
            config.AUTHORIZATION,
            config.AUTHORIZATIONPAGE_PASSWORD,
            config.AUTHORIZATIONPAGE_YUBIKEY,
            config.AUTHORIZATIONPAGE_PASSWORD_YUBIKEY,
            mako_lookup,
            authorization_url,
            config.PASSWD,
            config.CAS_SERVER,
            config.LDAP,
            config.LDAP_EXTRAVALIDATION,
            config.CAS_SERVICE_URL,
            sphandler,
            config.YUBIKEY_SERVER,
            config.YUBIKEY_DB
        )
        authz = AuthzHandling()

        provider = Provider(config.ISSUER, SessionDB(), cdb, ac, None, authz, verify_client, config.SYM_KEY, None,
                            "", None, "", mako_lookup, "verifyLogout.mako")
        provider.seed = seed

        if debug:
            provider.debug = True
        if test:
            provider.test_mode = True
        else:
            provider.test_mode = False

        #Adds the supported end points to the provider, to be returned.
        provider.endpoints = endpoints

        provider = self.setup_provider_cookie(provider, config.COOKIETTL, config.COOKIENAME)
        provider = self.setup_provider_url(provider, config.BASEURL, config.PORT)
        provider = self.setup_provider_keys(provider, logger, config.OP_PRIVATE_KEYS, config.OP_PUBLIC_KEYS)
        provider = self.setup_provider_userinfo(provider, config.AUTHORIZATION,
                                                config.USERINFO, config.LDAP, config.USERDB, sphandler)
        return provider

    def setup_provider_userinfo(self, provider, authorization, userinfo, ldap, userdb, sphandler):
        """
        Initialize the handler for taking care of user information request (read user info endpoint).
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
                          This class is a SAML SP and is used by the OpHandler to acts as a proxy against SAML IdP's.
        :param provider: The provider. (oic.oic.provider.Provider)
        :param authorization: A dictionary that defines what kind of authorization to use. Example:
         {
            "SAML" : {"ACR": "SAML", "WEIGHT": 3, "URL": "http://www.example.com", "USER_INFO": "SAML"},
            "CAS" : {"ACR": "CAS", "WEIGHT": 2, "URL": "http://www.example.com", "USER_INFO": "LDAP"},
            "PASSWORD" : {"ACR": "PASSWORD", "WEIGHT": 1, "URL": "http://www.example.com", "USER_INFO": "SIMPLE"},
            "MULTIPLEAUTHN" :   {
                                    "ACR": "MultipleAuthnTest",
                                    "WEIGHT": 4,
                                    "URL": ISSUER,
                                    "USER_INFO": "SAML",
                                    "AUTHNLIST": [
                                        {"ACR": "PASSWORD"},
                                        {"ACR": "CAS"},
                                        {"ACR": "SAML"}
                                    ]
                                }
         }
         The key SAML = Authorization against an IdP.
         The key CAS = Authorization is performed against a CAS server.
         The key PASSWORD = Authorization is performed with the selfcontained user/password authorization.
         The key MULTIPLEAUTHN = Authorization is performed with one or more of the methods above. The list is defined
                                 in AUTHNLIST.

         The key ACR = The value expected in acr_values.
         The key WEIGHT = The weight of the method. Higher is more secure.
         The key URL = URL to the service responsible for authentication.
         The key USER_INFO = Method to retrieve user info. Can be SAML (collected from an IdP), LDAP (collected from
                             a LDAP server or SIMPLE (collected defined in the parameter userdb)
        :param userinfo: Only used if USER_INFO is not correct configured in the map above.
                         This can be LDAP, SAML or SIMPLE.
                         If LDAP, then a LDAP server is used for user information.
                         If SIMPLE, then the configuration file is used.
                         If SAML, then a IdP is used.
        :param ldap:     LDAP configurations. For example:
                            {
                                "uri": "ldap://ldap.umu.se",
                                "base": "dc=umu, dc=se",
                                "filter_pattern": "(uid=%s)",
                                "user": "",
                                "passwd": "",
                                "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
                            }
        :param userdb:  User information in a dictionary. For example:
                         {
                            "diana": {
                                "user_id": "dikr0001",
                                "name": "Diana Krall",
                                "given_name": "Diana",
                                "family_name": "Krall",
                                "nickname": "Dina",
                                "email": "diana@example.org",
                                "email_verified": False,
                                "phone_number": "+46 90 7865000",
                                "address": {
                                    "street_address": "Umea Universitet",
                                    "locality": "Umea",
                                    "postal_code": "SE-90187",
                                    "country": "Sweden"
                                },
                        }
        :return: A updated provider. (oic.oic.provider.Provider)
        """
        #If different user info class should be used for different autentication methods.
        try:
            user_info_auth_map = {}
            for auth, value in authorization.items():
                acr = value[OpHandler.AUTHORIZATION_ACR]
                user_info = value[OpHandler.AUTHORIZATION_USER_INFO]
                user_info_auth_map[acr] = self.get_user_info(user_info, ldap, userdb, sphandler)
            provider.userinfo = UserInfoAuthHandler(self, user_info_auth_map)
            return provider
        except:
            pass

        #If only one user info is configured.
        provider.userinfo = self.get_user_info(userinfo, ldap, userdb, sphandler)
        return provider

    def get_user_info(self, userinfo, ldap, userdb, sphandler):
        """
        Creates an instance of a user information handle class for a oic.oic.provider.Provider.
        :param userinfo: A string that shold contain SAML, LDAP or SIMPLE.
        :param ldap:     LDAP configurations. For example:
                            {
                                "uri": "ldap://ldap.umu.se",
                                "base": "dc=umu, dc=se",
                                "filter_pattern": "(uid=%s)",
                                "user": "",
                                "passwd": "",
                                "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
                            }
        :param userdb:  User information in a dictionary. For example:
                         {
                            "diana": {
                                "user_id": "dikr0001",
                                "name": "Diana Krall",
                                "given_name": "Diana",
                                "family_name": "Krall",
                                "nickname": "Dina",
                                "email": "diana@example.org",
                                "email_verified": False,
                                "phone_number": "+46 90 7865000",
                                "address": {
                                    "street_address": "Umea Universitet",
                                    "locality": "Umea",
                                    "postal_code": "SE-90187",
                                    "country": "Sweden"
                                },
                        }
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
                          This class is a SAML SP and is used by the OpHandler to acts as a proxy against SAML IdP's.
        :return: Instance of a user information handle class for a oic.oic.provider.Provider.
        """
        if userinfo == OpHandler.USER_INFO_SAML:
            return sphandler.userinfo
        elif userinfo == OpHandler.USER_INFO_LDAP:
            from oic.utils.userinfo.ldap_info import UserInfoLDAP

            return UserInfoLDAP(**ldap)
        elif userinfo == OpHandler.USER_INFO_SIMPLE:
            return UserInfo(userdb)

    def setup_authorization(
        self,
        authorization,
        authorization_page_password,
        authorization_page_yubikey,
        authorization_page_password_yubikey,
        mako_lookup,
        authorization_url,
        passwd,
        cas_server,
        ldap_config,
        ldap_extra_config,
        cas_service_url,
        sphandler,
        yubikey_server,
        yubikey_db
    ):
        """
        Creates an instance of the class oic.utils.authn.authn_context.AuthnBroker that should handle the authentication
        for the provider (oic.oic.provider.Provider).
        :param cas_server:   URL to a CAS server.
        :param ldap_config:     LDAP configurations. For example:
                            {
                                "uri": "ldap://ldap.umu.se",
                                "base": "dc=umu, dc=se",
                                "filter_pattern": "(uid=%s)",
                                "user": "",
                                "passwd": "",
                                "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
                            }
        :param ldap_extra_config: Extra validations performed by the CAS module.
                               {
                                "verifyAttr": "eduPersonAffiliation",
                                "verifyAttrValid": ['employee', 'staff', 'student']
                               }
                               verifyAttr = The attribute to validate.
                               verifyAttrValid = Contains all valid values.
        :param cas_service_url:  The return URL to send to the CAS server.
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
                          This class is a SAML SP and is used by the OpHandler to acts as a proxy against SAML IdP's.
        :param authorization:       Type of authorization. See description in method setupProviderUserinfo.
        :param authorization_page_password:   The page to be used for username and password logins.
        :param authorization_page_yubikey:   The page to be used for username and yubikey logins.
        :param authorization_page_password_yubikey:   The page to be used for username, yubikey and password logins.
        :param mako_lookup:          A mako template lookup. (mako.lookup.TemplateLookup)
        :param authorization_url:    URL for handling authorization.
        :param passwd:              Username and password directory. For example:
                                        {
                                            "diana": "krall",
                                            "babs": "howes",
                                            "upper": "crust",
                                            "rohe0002": "StevieRay",
                                            "haho0032": "qwerty"
                                        }
        :param yubikey_db:  Database used by the yubikey client.
        :param yubikey_server URL to the yubikey validation server.
        :return: The object instance that should handle authorization.
        """
        ac = AuthnBroker()
        for authkey, value in authorization.items():
            authn = None
            if OpHandler.AUTHORIZATION_MULTIPLEAUTHN == authkey:
                authn_list = []

                authn_config_list = value[OpHandler.AUTHENTICATION_AUTHNLIST]
                for element in authn_config_list:
                    tmpauthn = self.get_authn(
                        element[OpHandler.AUTHORIZATION_ACR],
                        ldap_config, cas_server,
                        cas_service_url,
                        authorization_url,
                        ldap_extra_config,
                        authorization_page_password,
                        authorization_page_yubikey,
                        authorization_page_password_yubikey,
                        mako_lookup,
                        passwd,
                        sphandler,
                        yubikey_server,
                        yubikey_db
                    )
                    authn_list.append(tmpauthn)
                authn = MultipleAuthHandler(authn_list)
            else:
                authn = self.get_authn(authkey,
                                       ldap_config,
                                       cas_server,
                                       cas_service_url,
                                       authorization_url,
                                       ldap_extra_config,
                                       authorization_page_password,
                                       authorization_page_yubikey,
                                       authorization_page_password_yubikey,
                                       mako_lookup,
                                       passwd,
                                       sphandler,
                                       yubikey_server,
                                       yubikey_db)

            if authn is not None:
                ac.add(value[OpHandler.AUTHORIZATION_ACR],
                       authn,
                       value[OpHandler.AUTHORIZATION_WEIGHT],
                       value[OpHandler.AUTHORIZATION_URL])
        return ac

    def get_authn(self,
                  authkey,
                  ldap_config,
                  cas_server,
                  cas_service_url,
                  authorization_url,
                  ldap_extra_config,
                  authorization_page_password,
                  authorization_page_yubikey,
                  authorization_page_password_yubikey,
                  mako_lookup,
                  passwd,
                  sphandler,
                  yubikey_server,
                  yubikey_db):
        """
        Creates an instance of the class that should handle the authentication for the provider
        (oic.oic.provider.Provider).
        This class must implement oic.utils.authn.user.UserAuthnMethod.
        :param authkey:     All keys contained in an authorization dictionary.
                            See description in method setupProviderUserinfo.
        :param cas_server:   URL to a CAS server.
        :param ldap_config:     LDAP configurations. For example:
                            {
                                "uri": "ldap://ldap.umu.se",
                                "base": "dc=umu, dc=se",
                                "filter_pattern": "(uid=%s)",
                                "user": "",
                                "passwd": "",
                                "attr": ["eduPersonScopedAffiliation", "eduPersonAffiliation"],
                            }
        :param ldap_extra_config: Extra validations performed by the CAS module.
                               {
                                "verifyAttr": "eduPersonAffiliation",
                                "verifyAttrValid": ['employee', 'staff', 'student']
                               }
                               verifyAttr = The attribute to validate.
                               verifyAttrValid = Contains all valid values.
        :param cas_service_url:  The return URL to send to the CAS server.
        :param sphandler: An instance of the class pyOpSamlProxy.client.sp.handler.SpHandler.
                          This class is a SAML SP and is used by the OpHandler to acts as a proxy against SAML IdP's.
        :param authorization_page_password:   The page to be used for username and password logins.
        :param authorization_page_yubikey:   The page to be used for username and yubikey logins.
        :param authorization_page_password_yubikey:   The page to be used for username, yubikey and password logins.
        :param mako_lookup:          A mako template lookup. (mako.lookup.TemplateLookup)
        :param authorization_url:    URL for handling authorization.
        :param passwd:              Username and password directory. For example:
                                        {
                                            "diana": "krall",
                                            "babs": "howes",
                                            "upper": "crust",
                                            "rohe0002": "StevieRay",
                                            "haho0032": "qwerty"
                                        }
        :param yubikey_db:  Database used by the yubikey client.
        :param yubikey_server URL to the yubikey validation server.
        :return: The object instance that should handle authorization.
        """
        #authorization_page_yubikey,
        #authorization_page_password_yubikey,
        #yubikey_server,
        #yubikey_db
        if OpHandler.AUTHORIZATION_SAML == authkey:
            authn = sphandler.authnmethod
        elif OpHandler.AUTHORIZATION_CAS == authkey:
            ldap_extra_config.update(ldap_config)
            authn = CasAuthnMethod(None, cas_server, cas_service_url, authorization_url,
                                   UserLDAPMemberValidation(**ldap_extra_config))
        elif OpHandler.AUTHORIZATION_PASSWORD == authkey:
            authn = UsernamePasswordMako("login", None, authorization_page_password, mako_lookup, passwd,
                                         authorization_url, password_query_key="password")
        elif OpHandler.AUTHORIZATION_PASSWORD_YUBIKEY == authkey:
            authn = UsernamePasswordMako("login", None, authorization_page_password_yubikey, mako_lookup, passwd,
                                         authorization_url, password_query_key="password", yubikey_db=yubikey_db,
                                         yubikey_server=yubikey_server, yubikey_otp_key="otp")
        elif OpHandler.AUTHORIZATION_YUBIKEY == authkey:
            authn = UsernamePasswordMako("login", None, authorization_page_yubikey, mako_lookup, passwd,
                                         authorization_url, yubikey_db=yubikey_db, yubikey_server=yubikey_server,
                                         yubikey_otp_key="otp")
        return authn

    def setup_provider_keys(self, provider, logger, private_keys, public_keys_file):
        #Setting up keys for the provider.
        """
        Initializes the provider with RSA private and public key.
        :param provider: The provider. (oic.oic.provider.Provider)
        :param logger:   Log class.
        :param private_keys: File path to a pem file containing the private key.
        :param public_keys_file: File path to a json file containing the public key.
                                 This file should be exposed as downloadable in the web server.
        :return: A updated provider. (oic.oic.provider.Provider)
        """
        try:
            provider.keyjar[""] = []
            kbl = []
            for typ, info in private_keys.items():
                typ = typ.upper()
                logger.info("OC server key init: %s, %s" % (typ, info))
                kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                               keytype=typ)
                provider.keyjar.add_kb("", kb)
                kbl.append(kb)
            try:
                new_name = public_keys_file
                dump_jwks(kbl, new_name)
                provider.jwks_uri.append("%s%s" % (provider.baseurl, new_name))
            except KeyError:
                pass
            for b in provider.keyjar[""]:
                logger.info("OC3 server keys: %s" % b)
        except Exception, err:
            logger.error("Key setup failed: %s" % err)
            provider.key_setup("static", sig={"format": "jwk", "alg": "rsa"})
        return provider

    def setup_provider_url(self, provider, baseurl, port):
        """
        Setting up the base URL for the OP server.
        :param provider: The provider. (oic.oic.provider.Provider)
        :param baseurl: Baseurl for the server.
        :param port: Port for the server.
        :return: A updated provider. (oic.oic.provider.Provider)
        """
        if port == 80:
            provider.baseurl = baseurl
        else:
            if baseurl.endswith("/"):
                baseurl = baseurl[:-1]
            provider.baseurl = "%s:%d" % (baseurl, port)
        if not provider.baseurl.endswith("/"):
            provider.baseurl += "/"
        return provider

    def setup_provider_cookie(self, provider, ttl, name):
        """
        Setting up cookies for the provider
        :param provider: The provider. (oic.oic.provider.Provider)
        :param ttl: Time to live in minutes for the cookie.
        :param name: Name for the cookie.
        :return: Updated provider. (oic.oic.provider.Provider)
        """
        try:
            provider.cookie_ttl = ttl
        except AttributeError:
            pass
        try:
            provider.cookie_name = name
        except AttributeError:
            pass
        return provider

    def clear_op_handler_cache(self, environ):
        """
        Clears the OpHandlerCache instance for the current user.
        :param environ: WSGI enviroment.
        """
        uid = self.get_uid(environ)
        self.set_op_handler_cache(uid, None)

    def get_op_handler_cache(self, uid):
        """
        Retrieve the OpHandlerCache instance for the current user.
        :param uid: The userid for the current user.
        :return: The current users instance of the OpHandlerCache.
        """
        if uid not in self.ophandlercache or self.ophandlercache[uid] is None:
            self.ophandlercache[uid] = OpHandlerCache()
        return self.ophandlercache[uid]

    def set_op_handler_cache(self, uid, cache):
        """
        Set the OpHandlerCache instance for the current user.
        :param uid: The userid for the current user.
        :param cache: An instance of the class OpHandlerCache.
        """
        self.ophandlercache[uid] = cache

    def pick_auth(self, areq):
        res = self.provider.pick_auth(areq)
        if res is not None:
            return res[0]

    def setup_multiple_authn(self, environ):
        """
        Performs setup for the class pyOpSamlProxy.provider.op.util.MultipleAuthHandler.
        This method must be called before the provider (oic.oic.provider.Provider) calls this class.
        :param environ: WSGI enviroment.
        """
        areq = urlparse.parse_qs(environ.get("QUERY_STRING", ""))
        authn = self.pick_auth(areq)
        if type(authn) is MultipleAuthHandler:
            authn.ophandler = self

    def get_uid(self, environ):
        """
        Retrivies the user identification for the current user.
        Either from web session through cookies or from the access token.
        :param environ: WSGI enviroment.
        :return: The user identification.
        """
        areq = urlparse.parse_qs(environ.get("QUERY_STRING", ""))
        uid = self.get_sub_from_accesstoken(environ)
        if uid is not None:
            return uid
        authn = self.pick_auth(areq)
        try:
            identity = authn.authenticated_as(environ["HTTP_COOKIE"])
            return identity["uid"]
        except:
            return None

    def set_authentication(self, environ):
        """
        Sets the acr_value sen from the client in the current users OpHandlerCache.
        This method must be used to save the authentication method used by the user so the correct
        method for user information retrieval can be used when authentication methods have
        different user information retrieval methods.
        :param environ: WSGI enviroment.
        """
        uid = self.get_uid(environ)
        if uid is not None:
            cache = self.get_op_handler_cache(uid)
            #Only update the cache if it is not already set. You cannot change the authentication method
            #unless you first logout.
            areq = urlparse.parse_qs(environ["QUERY_STRING"])
            authn = self.pick_auth(areq)
            identity = authn.authenticated_as(environ["HTTP_COOKIE"])
            if cache.auth is None or self.provider.re_authenticate(areq, authn) or identity is None:
                _dict = HttpHandler.query_dictionary(environ)
                if self.ACR_VALUES in _dict and _dict[self.ACR_VALUES] is not None:
                    cache.auth = _dict[self.ACR_VALUES]
                    self.set_op_handler_cache(uid, cache)

    def get_authentication(self, environ):
        """
        Retrieve the authentication performed by the user.
        This is used to map the correct method for retrieving user information when authentication methods have
        different user information retrieval methods.
        :param environ: WSGI enviroment.
        :return: The acr_value the client sent for the current user while performing authentication.
        """
        uid = self.get_uid(environ)
        return self.get_op_handler_cache(uid).auth

    def get_sub_from_accesstoken(self, environ):
        """
        Get the user identification aka sub from the access token.
        If no access token exists, just carry on and return None.
        :param environ: WSGI enviroment.
        :return: User identification if it exists in the access token, otherwise None.
        """
        try:
            request = HttpHandler.query_dictionary(environ)
            _token = request["access_token"][0]
            _sdb = self.provider.sdb
            typ, key = _sdb.token.type_and_key(_token)
            session = _sdb[key]
            sub = session['sub']
            return sub
        except:
            return None

    def filter_auth_cookie(self, environ):
        """
        Even though if the user have a correct session cookie provided by the provider (oic.oic.provider.Provider)
        this method can remove it from the WSGI enviroment so the user will appear unauthorized to the provider.
        This is useful if when the Ophandler wants to make a user unauthorized without performing a redirect and
        saving the cookie.
        :param environ: WSGI enviroment.
        """
        cookie_name = self.provider.cookie_name
        cookie_string = None
        cookie_list = environ["HTTP_COOKIE"].split(";")
        for cookie in cookie_list:
            cookie_split = cookie.split("=")
            name = cookie_split[0]
            value = cookie_split[1]
            if name != cookie_name:
                if cookie_string is None:
                    cookie_string = name + "=" + value
                else:
                    cookie_string += ";" + name + "=" + value
        environ["HTTP_COOKIE"] = cookie_string

    def verify_session(self, environ, session):
        """
        Verifies if the session has been invalidated, but not yet cleaned due to technical issues.
        If the session is invalidated, perform a cleanup.
        :param environ: WSGI enviroment.
        """
        if OpHandler.CLEARSESSION in session and self.session_cache[session[OpHandler.CLEARSESSION]] is not None and \
           self.session_cache[session[OpHandler.CLEARSESSION]] is not True:
            self.clear_user_data(environ, session)
        if OpHandler.CLEARSESSION not in session or session[OpHandler.CLEARSESSION] is None:
            session[OpHandler.CLEARSESSION] = uuid.uuid4().urn
            self.session_cache[session[OpHandler.CLEARSESSION]] = True

    def clear_user_data(self, environ, session):
        """
        Clear all information saved about the user that has been saved by this class or
        pyOpSamlProxy.client.sp.handler.SpHandler.
        :param environ: WSGI enviroment.
        """
        self.session_cache[session[OpHandler.CLEARSESSION]] = False
        self.sphandler.clear_sp_handler_cache(environ, session)
        self.clear_op_handler_cache(environ)
        session.clear_session()

    def set_saml_response(self, samlresponse):
        """
        Sets the kind of user information response the pyOpSamlProxy.client.sp.handler.UserInfoSpHandler instance
        should give. If samlresponse is true, the information sent to the client will be the compelete response from
        the Idp. If samlresponse is false the information retrieved from the IdP will be mapped to OpenId connect
        userinfo endpoint.
        :param samlresponse: See above.
        """
        userinfo_type = type(self.provider.userinfo)
        if userinfo_type is UserInfoAuthHandler:
            self.provider.userinfo.set_saml_response(samlresponse)
        elif userinfo_type is UserInfoSpHandler:
            self.provider.userinfo.samlresponse = samlresponse

    def verify_provider_requests(self, path):
        """
        Verifies if the provider is responsible for handling the request.
        :param path: The requested path.
        :return: True if this class should handle this request, otherwise false.
        """
        for regex, callback in self.urlmap:
            match = re.search(regex, path)
            if match is not None:
                return True
        return False

    def handle_provider_requests(self, environ, start_response, path, session):
        """
        Handles all url:s that are intended for the provider.
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: The response created by underlying methods.
        """
        self.session = session
        self.verify_session(environ, session)
        for regex, callback in self.urlmap:
            match = re.search(regex, path)
            if match is not None:
                try:
                    #Makes it possible for pyoidc to get hold of the arguments.
                    environ['oic.url_args'] = match.groups()[0]
                except IndexError:
                    #Makes it possible for pyoidc to get hold of the arguments.
                    environ['oic.url_args'] = path
                self.logger.info("callback: %s" % callback)
                try:
                    #Methods are defined in self.endpoints and self.urlmaps
                    callback_response = callback(environ, start_response)
                    return callback_response
                except Exception, err:
                    print >> sys.stderr, "%s" % err
                    message = traceback.format_exception(*sys.exc_info())
                    print >> sys.stderr, message
                    self.logger.exception("%s" % err)
                    raise err

                    #Below is methods that catches client requests.

    def webfinger(self, environ, start_response):
        """
        Answers to a webfinger request.
        If you only have the name of the user (a resource) can ask for the the discovery endpoint.

        ==STEP 1==
        Example request:
        REQUEST_METHOD:GET
        Path:  well-known/webfinger
        Query:
            {
                'resource': ['https://haho0034@hashog.umdc.umu.se:8999'],
                'rel': ['http://openid.net/specs/connect/1.0/issuer']
            }

        Response:
            ['{
                "expires": "2013-09-17T08:27:32Z",
                "links": [{ "href": "https://localhost:8999/",
                            "rel": "http://openid.net/specs/connect/1.0/issuer"
                         }],
                "subject": "https://haho0034@hashog.umdc.umu.se:8999"
            }']

        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: oic.utils.http_util.Response object.
        """
        query = parse_qs(environ["QUERY_STRING"])
        try:
            assert query["rel"] == [OIC_ISSUER]
            resource = query["resource"][0]
        except KeyError:
            resp = http_util.BadRequest("Missing parameter in request.")
        else:
            wf = WebFinger()
            resp = http_util.Response(wf.response(subject=resource, base=self.provider.baseurl))
        return resp(environ, start_response)

    def verify_client_id(self, environ, start_response):
        areq = urlparse.parse_qs(environ.get("QUERY_STRING", ""))
        try:
            client = self.provider.cdb[areq["client_id"][0]]
            return http_util.Response()(environ, start_response)
        except:
            return http_util.BadRequest(message="No such client.")(environ, start_response)

    def op_info(self, environ, start_response):
        """
        Provides configuration information about the provider.

        ==STEP 2==
        Example request:
        REQUEST_METHOD:GET
        Path:  well-known/openid-configuration
        Query:
            {
            }

        Response:
        ['{
            "claims_supported": ["profile", "openid", "offline_access", "phone", "address", "email"],
            "subject_types_supported": ["public", "pairwise"],
            "request_parameter_supported": "true",
            "userinfo_signing_alg_values_supported":
                ["HS512", "none", "RS256", "ES256", "HS256", "RS512", "HS384", "RS384"],
            "issuer": "https://localhost:8999/",
            "id_token_encryption_enc_values_supported": ["A128CBC-HS256", "A256CBC-HS512", "A256GCM"],
            "require_request_uri_registration": "true",
            "grant_types_supported": ["authorization_code", "implicit", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
            "token_endpoint": "https://localhost:8999/token",
            "request_uri_parameter_supported": "true",
            "version": "3.0",
            "registration_endpoint": "https://localhost:8999/registration",
            "jwks_uri": "https://localhost:8999/static/jwks.json",
            "userinfo_encryption_alg_values_supported": ["RSA1_5", "RSA-OAEP"],
            "scopes_supported": ["openid"],
            "token_endpoint_auth_methods_supported":
                ["client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt"],
            "userinfo_encryption_enc_values_supported": ["A128CBC-HS256", "A256CBC-HS512", "A256GCM"],
            "id_token_signing_alg_values_supported":
                ["HS512", "none", "RS256", "ES256", "HS256", "RS512", "HS384", "RS384"],
            "request_object_encryption_enc_values_supported": ["A128CBC-HS256", "A256CBC-HS512", "A256GCM"],
            "claims_parameter_supported": "true",
            "token_endpoint_auth_signing_alg_values_supported":
                ["HS512", "none", "RS256", "ES256", "HS256", "RS512", "HS384", "RS384"],
            "userinfo_endpoint": "https://localhost:8999/userinfo",
            "request_object_signing_alg_values_supported":
                ["HS512", "none", "RS256", "ES256", "HS256", "RS512", "HS384", "RS384"],
            "request_object_encryption_alg_values_supported": ["RSA1_5", "RSA-OAEP"],
            "response_types_supported":
                ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
            "id_token_encryption_alg_values_supported": ["RSA1_5", "RSA-OAEP"],
            "authorization_endpoint": "https://localhost:8999/authorization",
            "claim_types_supported": ["normal", "aggregated", "distributed"]}']

        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: oic.utils.http_util.Response object.
        """
        self.logger.info("op_info")
        return wsgi_wrapper(environ, start_response, self.provider.providerinfo_endpoint, logger=self.logger)

    def registration(self, environ, start_response):
        """
        Registers a client with the provider.

        ==STEP 3==
        Example request:
        CONTENT_TYPE:   application/json
        REQUEST_METHOD: POST
        Path:           registration
        Query:
                        {
                            u'application_type': u'web',
                            u'redirect_uris': [u'http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899'],
                            u'contacts': [u'ops@example.com']
                        }

        Response:
                        ['{
                            "client_id_issued_at": 1379409400,
                            "redirect_uris": ["http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899"],
                            "contacts": ["ops@example.com"],
                            "application_type": "web",
                            "registration_client_uri": "https://localhost:8999/registration?client_id=vnQeHhnKp1IT",
                            "registration_access_token": "yjDt7ojgEWTTF6QOVOLYB8A2j2plJRny",
                            "client_id": "vnQeHhnKp1IT",
                            "client_secret": "7a4b548cdfd1090020918cc550c92981dc4cc67556b87e6306a0c788",
                            "client_secret_expires_at": 1379495800}']

        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: ????
        """
        if environ["REQUEST_METHOD"] == "POST":
            return wsgi_wrapper(environ, start_response, self.provider.registration_endpoint,
                                logger=self.logger)
        elif environ["REQUEST_METHOD"] == "GET":
            return wsgi_wrapper(environ, start_response, self.provider.read_registration,
                                logger=self.logger)
        else:
            return ServiceErrorException("Method not supported")

    def authorization(self, environ, start_response):
        """
        Handles an OIDC/OAuth authorization request.

        ==STEP 4 and 6==
        Example request:
        REQUEST_METHOD: GET
        Path:           authorization
        Query:
                        {
                            'scope': 'openid profile email address phone',
                            'state': 'urn:uuid:0e3c5a07-5cbc-4d2b-9dce-662369286123',
                            'redirect_uri': 'http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899',
                            'response_type': 'code',
                            'client_id': 'vnQeHhnKp1IT'
                        }

        Response:       A way for the user to perform authentication. For example a login page.

        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: oic.utils.http_util.Response object.
        """
        self.set_saml_response(False)
        self.setup_multiple_authn(environ)
        self.set_authentication(environ)
        resp = wsgi_wrapper(environ, start_response, self.provider.authorization_endpoint,
                            logger=self.logger)
        return resp

    def verify(self, environ, start_response):
        """
        Validates an authentication.

        ==STEP 5==
        For example when a username/password have been performed:

        REQUEST_METHOD: GET
        Path:           verify
        Query:
                        {
                            'query': 'scope=openid+profile+email+address+phone&
                                      state=urn%3Auuid%3Aa0f02999-5fbd-4f2a-ac01-2d7e463e78ca&
                                      redirect_uri=http%3A%2F%2Flocalhost%3A8666%2F6C5807EE3599CA38F763BFD0E24A2899&
                                      response_type=code&
                                      client_id=4oz3IJtsACIT',
                            'login': 'haho0032',
                            'password': 'qwerty'
                        }

        Response:
                        ['
                            <html>\n
                                <head>
                                    <title>Redirecting to
                                        http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899?
                                        scope=openid+profile+email+address+phone&
                                        state=urn%3Auuid%3Aa0f02999-5fbd-4f2a-ac01-2d7e463e78ca&
                                        code=EPUCxsxDoq1ye%2FjPMqzyE9%2F68fgxNGAW%2BEg0tofPhb6L7DhPuhVzkILekp%2F6Al5U
                                    </title>
                                </head>\n
                                <body>
                                \nYou are being redirected to
                                <a href="http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899?
                                scope=openid+profile+email+address+phone&
                                state=urn%3Auuid%3Aa0f02999-5fbd-4f2a-ac01-2d7e463e78ca&
                                code=EPUCxsxDoq1ye%2FjPMqzyE9%2F68fgxNGAW%2BEg0tofPhb6L7DhPuhVzkILekp%2F6Al5U">
                                http://localhost:8666/6C5807EE3599CA38F763BFD0E24A2899?
                                scope=openid+profile+email+address+phone&
                                state=urn%3Auuid%3Aa0f02999-5fbd-4f2a-ac01-2d7e463e78ca&
                                code=EPUCxsxDoq1ye%2FjPMqzyE9%2F68fgxNGAW%2BEg0tofPhb6L7DhPuhVzkILekp%2F6Al5U</a>\n
                                </body>\n
                            </html>'
                        ]


        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: oic.utils.http_util.Response object.
        """
        self.setup_multiple_authn(environ)
        return wsgi_wrapper(environ, start_response, self.provider.verify_endpoint,
                            logger=self.logger)

    def token(self, environ, start_response):
        """
        Handles requests for access token.

         ==STEP 7==
        CONTENT_TYPE:   application/x-www-form-urlencoded
        REQUEST_METHOD: POST
        Path:           token
        Query:
                        {
                            'redirect_uri': ['http://hashog.umdc.umu.se:8666/6C5807EE3599CA38F763BFD0E24A2899'],
                            'client_secret': ['8b05f244e854bd3613ce2190bb738b3e7b36a8d48615eaf9751fea70'],
                            'code': ['k9ABkkDHbsde7AUYd0qjdGCWOJHz7c6/nZ1mII3aNkov9rXrWPpaMO56qSz7UX8a'],
                            'client_id': ['m9QDtk3fMNK3'],
                            'grant_type': ['authorization_code']
                        }
        response:
                        ['{
                            "access_token": "47/ElqDBgOjBsXmUBHvtH4zfHA5vl09+suH2OFdQFI+ucLlplHFlrX9zY9qGAgMK",
                            "id_token": "eyJhbGciOiJSUzI1NiJ9.eyJhdWQiOiBbIktCc3pIT3pvTHd0QyJdLCAiaXNz
                                         IjogImh0dHBzOi8vbG9jYWxob3N0Ojg5OTkiLCAiYWNyIjogIjIiLCAiZXhwI
                                         jogMTM3OTUwMDk1NSwgImlhdCI6IDEzNzk0MjE3NTUsICJzdWIiOiAiaGFobz
                                         AwMzIifQ.zKB5GaAzkG8sUClBu8Zr8cZJj0XFxipLALtuyWz6nVVuklS39jmi
                                         pOoWgJdSRioWv43akscdw_7k3OKXR4pH8hW4DoETdQJdkewO0eI9vXRVzP24g
                                         EYOhgRaR_Yh682ogykU4xihQgvD_gxT33CG3FOoMzA6sEk2Q2LBD63NECmMbK
                                         0Xrweq5k9jJfPW1TFEiogQBc7Y2n6V8QAgxZSLGmcddPKIqaLL5uypDOG875j
                                         awN9wn2LrXp8MOnrrtD2XUCog53E6NtT30I0nrlW_wbEkyd4pmGrgrSrecM-d
                                         ZnGLOER-C-99Xy2fSGbIjOfQdKYVy4gmPRPcLxXL4LxLDw",
                            "expires_in": 3600,
                            "token_type": "Bearer",
                            "state": "urn:uuid:6b2e681f-1ca7-42d3-9133-bd77218d6cc7",
                            "scope": "openid profile email address phone",
                            "refresh_token": "47/ElqDBgOjBsXmUBHvtHxbios72FPU66HmaWwGoBaYotCC9hgU2wT0DMpR+Lpls"
                        }']
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: oic.utils.http_util.Response object.
        """
        return wsgi_wrapper(environ, start_response, self.provider.token_endpoint,
                            logger=self.logger)

    def userinfo(self, environ, start_response):
        """
        Handles requests for information about a user.
        ==STEP 8==
        CONTENT_TYPE:   application/x-www-form-urlencoded
        REQUEST_METHOD: POST
        Path:           userinfo
        Query:          {'access_token': ['k9ABkkDHbsde7AUYd0qjdIBFdfCjw8zqcis9dhxDX/tYWCrW6iME9veAT1EObisD']}
        response:
                        ['{
                            "phone_number": "+46 90 7865000",
                            "family_name": "H\\u00f6rberg",
                            "name": "Hans H\\u00f6rberg",
                            "email_verified": false,
                            "given_name": "Hans",
                            "address": {"country": "Sweden",
                                        "postal_code": "SE-90187",
                                        "street_address": "Ume\\u00e5 Universitet",
                                        "locality": "Ume\\u00e5"},
                            "nickname": "Hasse",
                            "email": "hans@example.org",
                            "sub": "haho0032"
                        }']
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return: User information
        """

        #If the user is validated with the SPHandler, the attribute data must be validated.
        #If the attribute data is not valid the RP must perform a new login.
        self.set_saml_response(False)
        resp = self.sphandler.userinfo.verify_information(environ, self.session)
        if resp:
            return wsgi_wrapper(environ, start_response, self.provider.userinfo_endpoint,
                                logger=self.logger)
        else:
            return resp(environ, start_response)

    def samluserinfo(self, environ, start_response):
        """
        See method userinfo.
        ==STEP 8==
        The only difference is that this method will return the complete saml response and not map the values
        to OpenId connect.
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return:
        """
        self.set_saml_response(True)
        resp = self.sphandler.userinfo.verify_information(environ, self.session)
        if resp:
            return wsgi_wrapper(environ, start_response, self.provider.userinfo_endpoint,
                                logger=self.logger)
        else:
            return resp(environ, start_response)

    def endsession(self, environ, start_response):
        """
        Logouts the user from the OP if he wishes to. The user must respond to a yes/no page before the user is
        logged out.
        ==STEP 9==
        INFO CONTENT_TYPE:GET
        Path:endsession
        Query:
            {'post_logout_redirect_uri': 'http://hashog.umdc.umu.se:8666/',
             'id_token_hint': 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiAiaGFobzAwMzIiLCAiYWNyIjogIjIiLCAiaXNzIjogImh0d
                               HBzOi8vbG9jYWxob3N0Ojg5OTkiLCAiYXRfaGFzaCI6ICJKYW9yTGxfU3lMU1d1QXFMT2tpSGp3Iiw
                               gImV4cCI6IDEzODA3MjA0MzgsICJpYXQiOiAxMzgwNjQxMjM4LCAiYXVkIjogWyJETUI1MEQxYzZET
                               WQiXX0.4XaCEaF3KCsCoAI_ER-ywy0uM2IPBONMefBsC-rJKHw',
             'key': 'urn:uuid:7cf6e141-2c5f-48c4-a800-e7cfd14387ab'
            }
        response: Redirect to yes/no page verifyLogout.mako and then redirect back to the client.
        :param environ: WSGI enviroment.
        :param start_response: WSGI start response.
        :return:
        """
        resp = wsgi_wrapper(environ, start_response, self.provider.end_session_endpoint, logger=self.logger)
        if self.provider.is_session_revoked(environ["QUERY_STRING"], environ["HTTP_COOKIE"]):
            self.clear_user_data(environ, self.session)
        return resp


