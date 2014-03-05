from auth.base import Authenticate
from dirg_util.aes import AESCipher
from saml2.httputil import Redirect
from saml2.s_utils import rndstr

__author__ = 'haho0032'
import logging

logger = logging.getLogger("pyOpSamlProxy.provider.idp.auth.util")


class IdPAuthentication(object):
    QUERY_PARAM = "query"
    AUTHN_REFERENCE_PARAM = "authn_reference"

    def __init__(self, idphandler):
        self.base_auth = Authenticate(cookie_object=idphandler.idp_server)
        self.idphandler = idphandler
        self.aes = AESCipher(self.idphandler.idp_server.symkey, self.idphandler.idp_server.iv)

    def authenticate(self, environ, start_response, reference, key, redirect_uri, **kwargs):
        raise NotImplementedError("The method not implemented")

    def verify_bool(self, environ, start_response):
        raise NotImplementedError("The method not implemented")

    def verify(self, environ, start_response):
        raise NotImplementedError("The method not implemented")

    def information(self, environ, start_response, uid):
        raise NotImplementedError("The method not implemented")

    def extra(self, environ, start_response, uid):
        raise NotImplementedError("The method not implemented")

    def get_authn_reference(self, query):
        if query is not None:
            if self.AUTHN_REFERENCE_PARAM in query and query[self.AUTHN_REFERENCE_PARAM] is not None:
                return query[self.AUTHN_REFERENCE_PARAM]
            elif self.QUERY_PARAM in query and query[self.QUERY_PARAM] is not None:
                query_dict = self.decrypt_dict(query[self.QUERY_PARAM])
                if self.AUTHN_REFERENCE_PARAM in query_dict:
                    return query_dict[self.AUTHN_REFERENCE_PARAM]
        return None

    def encrypt_dict(self, dictionary):
        message = ""
        first = True
        for key, value in dictionary.iteritems():
            if not first:
                message += ","
            message += key + "::" + value
            first = False
        return self.aes.encrypt(message)

    def decrypt_dict(self, message):
        dictionary = {}
        if message is not None and len(message) > 1:
            message = self.aes.decrypt(message)
            items = message.split(",")
            for item in items:
                values = item.split("::")
                if len(values) == 2:
                    dictionary[values[0]] = values[1]
        return dictionary

    def setup_idp(self, user, reference, redirect_uri, key):
        uid = rndstr(24)
        self.idphandler.idp_server.cache.uid2user[uid] = user
        self.idphandler.idp_server.cache.user2uid[user] = uid
        logger.debug("Register %s under '%s'" % (user, uid))
        cookie = self.idphandler.set_authorization_cookie(uid, reference)
        lox = "%s?id=%s&key=%s" % (redirect_uri, uid,
                                   key)
        logger.debug("Redirect => %s" % lox)
        resp = Redirect(lox, headers=[cookie], content="text/html")
        return resp

