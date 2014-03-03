from saml2.authn_context import PASSWORD, UNSPECIFIED
from saml2.samlp import authn_query_from_string

__author__ = 'haho0032'
import logging
import threading
from saml2.httputil import Response, geturl
import base64
from hashlib import sha1
from idproxy.util.saml import Service
from saml2 import BINDING_URI
from saml2 import BINDING_PAOS
from saml2 import BINDING_SOAP
from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.httputil import NotFound
from saml2.httputil import Unauthorized
from saml2.httputil import BadRequest
from saml2.httputil import ServiceError
from saml2.ident import Unknown
from saml2.s_utils import rndstr, exception_trace
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import PolicyError
from saml2.sigver import verify_redirect_signature


#Add a logger for this class.
logger = logging.getLogger("pyOpSamlProxy.provider.idp.util")
lock = threading.Lock()

class AuthCookie(object):
    def __init__(self, uid=None, authn_ref = None):
        self.uid = uid
        self.authn_ref = authn_ref

#Cache object for the IdP.
class Cache(object):
    def __init__(self, cache_1=None, cache_2=None):
        if cache_1 is None: cache_1 = {}
        if cache_2 is None: cache_2 = {}
        self.user2uid = {}
        self.uid2user = {}

# -----------------------------------------------------------------------------
# === Single log in ====
# -----------------------------------------------------------------------------
#Copy from pysaml2 example/idp2
class SSO(Service):
    REPOZE_ID_EQUIVALENT = "uid"

    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.binding = ""
        self.response_bindings = None
        self.resp_args = {}
        self.binding_out = None
        self.destination = None
        self.req_info = None
        self.idphandler = idphandler

    def verify_request(self, query, binding):
        """
        :param query: The SAML query, transport encoded
        :param binding: Which binding the query came in over
        """
        resp_args = {}
        if not query:
            logger.info("Missing QUERY")
            resp = Unauthorized('Unknown user')
            return resp_args, resp(self.environ, self.start_response)

        if not self.req_info:
            self.req_info = self.idphandler.idp_server.parse_authn_request(query, binding)

        if self.idphandler.copy_sp_cert:
                with lock:
                    self.req_info = self.idphandler.idp_server.parse_authn_request(query, binding)
                    cert_str = self.idphandler.idp_server.getvalid_certificate_str()
        else:
            self.req_info = self.idphandler.idp_server.parse_authn_request(query, binding)


        logger.info("parsed OK")
        _authn_req = self.req_info.message
        logger.debug("%s" % _authn_req)

        self.binding_out, self.destination = self.idphandler.idp_server.pick_binding(
            "assertion_consumer_service",
            bindings=self.response_bindings,
            entity_id=_authn_req.issuer.text)

        logger.debug("Binding: %s, destination: %s" % (self.binding_out,
                                                       self.destination))

        resp_args = {}
        try:
            resp_args = self.idphandler.idp_server.response_args(_authn_req)
            _resp = None
        except UnknownPrincipal, excp:
            _resp = self.idphandler.idp_server.create_error_response(_authn_req.id,
                                              self.destination, excp)
        except UnsupportedBinding, excp:
            _resp = self.idphandler.idp_server.create_error_response(_authn_req.id,
                                              self.destination, excp)

        return resp_args, _resp

    def not_authn(self, key, requested_authn_context, cert_str=None):
        redirect_uri = geturl(self.environ, query=False)
        self.logger.debug("Do authentication")
        auth_info = self.idphandler.authn_broker.pick(requested_authn_context)
        if len(auth_info):
            method, reference = auth_info[0]
            logger.debug("Authn chosen: %s (ref=%s)" % (method, reference))
            return method.authenticate(self.environ, self.start_response, reference, key, redirect_uri,
                                       certificate_str=cert_str)
        else:
            resp = Unauthorized("No usable authentication method")
            return resp(self.environ, self.start_response)

    def do(self, query, binding_in, relay_state="", mtype=None):
        try:
            resp_args, _resp = self.verify_request(query, binding_in)
        except UnknownPrincipal, excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)

        assertion = None
        encrypted_assertion = None
        if not _resp:
            identity = {}

            authn = self.idphandler.authn_broker[self.idphandler.auth_cookie.authn_ref]
            method = None
            override_sign_assertion = None
            override_encrypt_assertion = None
            if authn:
                method = authn["method"]
            if method:
                identity = method.information(self.environ, self.start_response, self.user)
                try:
                    assertion = method.assertion(self.environ, self.start_response, self.user)
                    encrypted_assertion = method.encrypted_assertion(self.environ, self.start_response, self.user)
                    override_sign_assertion = True
                    if (encrypted_assertion is not None):
                        override_encrypt_assertion = True
                except Exception:
                    pass

            logger.info("Identity: %s" % (identity,))

            if self.REPOZE_ID_EQUIVALENT:
                identity[self.REPOZE_ID_EQUIVALENT] = self.user
            try:
                sign_assertion = self.idphandler.idp_server.config.getattr("sign_assertion", "idp")
                if sign_assertion is None:
                    sign_assertion = False
                if override_sign_assertion is not None:
                    sign_assertion = override_sign_assertion
                _resp = self.idphandler.idp_server.create_authn_response(
                    identity, userid=self.user,
                    authn=self.idphandler.authn_broker[self.idphandler.auth_cookie.authn_ref],
                    sign_assertion=sign_assertion,
                    sign_response=False,
                    **resp_args)
            except Exception, excp:
                logging.error(exception_trace(excp))
                resp = ServiceError("Exception: %s" % (excp,))
                return resp(self.environ, self.start_response)

        if assertion is not None or encrypted_assertion is not None:
            split_name = "Assertion"
            if encrypted_assertion is not None:
                split_name = "EncryptedAssertion"
                assertion = encrypted_assertion

            xml_str = str(_resp)
            xml_str_list = xml_str.split(split_name)

            start_index = (xml_str_list[0][::-1].find("<")) * -1
            _resp = xml_str_list[0][:(start_index-1)] + assertion + xml_str_list[2][1:]
            name1 = assertion[assertion.find('<')+1:assertion.find(':')]
            name2 = xml_str_list[0][len(xml_str_list[0])+start_index:-1]
            _resp.replace(name2, name1)


        logger.info("AuthNResponse: %s" % _resp)
        http_args = self.idphandler.idp_server.apply_binding(self.binding_out,
                                      "%s" % _resp, self.destination,
                                      relay_state, response=True)
        logger.debug("HTTPargs: %s" % http_args)
        return self.response(self.binding_out, http_args)

    def _store_request(self, _dict):
        logger.debug("_store_request: %s" % _dict)
        key = sha1(_dict["SAMLRequest"]).hexdigest()
        # store the AuthnRequest
        self.idphandler.idp_server.ticket[key] = _dict
        return key

    def redirect(self):
        """ This is the HTTP-redirect endpoint """
        logger.info("--- In SSO Redirect ---")
        _info = self.unpack_redirect()
        cert_str = None
        try:
            _key = _info["key"]
            _info = self.idphandler.idp_server.ticket[_key]
            self.req_info = _info["req_info"]
            del self.idphandler.idp_server.ticket[_key]
        except KeyError:
            if self.idphandler.copy_sp_cert:
                with lock:
                    self.req_info = self.idphandler.idp_server.parse_authn_request(_info["SAMLRequest"],
                                                            BINDING_HTTP_REDIRECT)
                    cert_str = self.idphandler.idp_server.getvalid_certificate_str()
            else:
                self.req_info = self.idphandler.idp_server.parse_authn_request(_info["SAMLRequest"],
                                                            BINDING_HTTP_REDIRECT)
            _req = self.req_info.message

            if "SigAlg" in _info and "Signature" in _info:  # Signed request
                issuer = _req.issuer.text
                _certs = self.idphandler.idp_server.metadata.certs(issuer, "any", "signing")
                verified_ok = False
                for cert in _certs:
                    if verify_redirect_signature(_info, cert):
                        verified_ok = True
                        break
                if not verified_ok:
                    resp = BadRequest("Message signature verification failure")
                    return resp(self.environ, self.start_response)

            if self.user:
                if _req.force_authn:
                    _info["req_info"] = self.req_info
                    key = self._store_request(_info)
                    return self.not_authn(key, _req.requested_authn_context, cert_str)
                else:
                    return self.operation(_info, BINDING_HTTP_REDIRECT)
            else:
                _info["req_info"] = self.req_info
                key = self._store_request(_info)
                return self.not_authn(key, _req.requested_authn_context, cert_str)
        else:
            return self.operation(_info, BINDING_HTTP_REDIRECT)

    def post(self):
        """
        The HTTP-Post endpoint
        """
        logger.info("--- In SSO POST ---")
        _info = self.unpack_either()
        cert_str = None
        if self.idphandler.copy_sp_cert:
            with lock:
                self.req_info = self.idphandler.idp_server.parse_authn_request(_info["SAMLRequest"],
                                                        BINDING_HTTP_POST)
                cert_str = self.idphandler.idp_server.getvalid_certificate_str()
        else:
            self.req_info = self.idphandler.idp_server.parse_authn_request(_info["SAMLRequest"],
                                                        BINDING_HTTP_POST)
        _req = self.req_info.message
        if self.user:
            if _req.force_authn:
                _info["req_info"] = self.req_info
                key = self._store_request(_info)
                return self.not_authn(key, _req.requested_authn_context, cert_str)
            else:
                return self.operation(_info, BINDING_HTTP_POST)
        else:
            _info["req_info"] = self.req_info
            key = self._store_request(_info)
            return self.not_authn(key, _req.requested_authn_context, cert_str)

    def ecp(self):
        # The ECP interface
        logger.info("--- ECP SSO ---")
        resp = None

        try:
            authz_info = self.environ["HTTP_AUTHORIZATION"]
            if authz_info.startswith("Basic "):
                _info = base64.b64decode(authz_info[6:])
                logger.debug("Authz_info: %s" % _info)
                try:
                    (user, passwd) = _info.split(":")
                    #TODO USE THE SAME AUTHORIZATION MODULE AS FOR SIMPLE USERNAME/PASSWORD
                    #See password.py
                    #if PASSWD[user] != passwd:
                    #    resp = Unauthorized()
                    self.user = user
                except ValueError:
                    resp = Unauthorized()
            else:
                resp = Unauthorized()
        except KeyError:
            resp = Unauthorized()

        if resp:
            return resp(self.environ, self.start_response)

        _dict = self.unpack_soap()
        self.response_bindings = [BINDING_PAOS]
        # Basic auth ?!
        return self.operation(_dict, BINDING_SOAP)

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------
#Copy from pysaml example/idp2
class SLO(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, request, binding, relay_state="", mtype=None):
        logger.info("--- Single Log Out Service ---")
        try:
            _, body = request.split("\n")
            logger.debug("req: '%s'" % body)
            req_info = self.idphandler.idp_server.parse_logout_request(body, binding)
        except Exception, exc:
            logger.error("Bad request: %s" % exc)
            resp = BadRequest("%s" % exc)
            return resp(self.environ, self.start_response)

        msg = req_info.message
        if msg.name_id:
            lid = self.idphandler.idp_server.ident.find_local_id(msg.name_id)
            logger.info("local identifier: %s" % lid)
            del self.idphandler.idp_server.cache.uid2user[self.idphandler.idp_server.cache.user2uid[lid]]
            del self.idphandler.idp_server.cache.user2uid[lid]
            # remove the authentication
            try:
                self.idphandler.idp_server.session_db.remove_authn_statements(msg.name_id)
            except KeyError, exc:
                logger.error("ServiceError: %s" % exc)
                resp = ServiceError("%s" % exc)
                return resp(self.environ, self.start_response)

        resp = self.idphandler.idp_server.create_logout_response(msg, [binding])

        try:
            hinfo = self.idphandler.idp_server.apply_binding(binding, "%s" % resp, "", relay_state)
        except Exception, exc:
            logger.error("ServiceError: %s" % exc)
            resp = ServiceError("%s" % exc)
            return resp(self.environ, self.start_response)

        #_tlh = dict2list_of_tuples(hinfo["headers"])
        delco = self.idphandler.delete_authorization_cookie(self.environ)
        if delco:
            hinfo["headers"].append(delco)
        logger.info("Header: %s" % (hinfo["headers"],))
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Assertion ID request ===
# ----------------------------------------------------------------------------
# Only URI binding
#Copy from pysaml example/idp2
class AIDR(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, aid, binding, relay_state="", mtype=None):
        logger.info("--- Assertion ID Service ---")

        try:
            assertion = self.idphandler.idp_server.create_assertion_id_request_response(aid)
        except Unknown:
            resp = NotFound(aid)
            return resp(self.environ, self.start_response)

        hinfo = self.idphandler.idp_server.apply_binding(BINDING_URI, "%s" % assertion, response=True)

        logger.debug("HINFO: %s" % hinfo)
        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

    def operation(self, _dict, binding, **kwargs):
        logger.debug("_operation: %s" % _dict)
        if not _dict or "ID" not in _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)

        return self.do(_dict["ID"], binding, **kwargs)

# ----------------------------------------------------------------------------
# === Artifact resolve service ===
# ----------------------------------------------------------------------------
#Copy from pysaml example/idp2
class ARS(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler
    def do(self, request, binding, relay_state="", mtype=None):
        _req = self.idphandler.idp_server.parse_artifact_resolve(request, binding)

        msg = self.idphandler.idp_server.create_artifact_response(_req, _req.artifact.text)

        hinfo = self.idphandler.idp_server.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# Manage Name ID service
# ----------------------------------------------------------------------------
#Copy from pysaml example/idp2
class NMI(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, query, binding, relay_state="", mtype=None):
        logger.info("--- Manage Name ID Service ---")
        req = self.idphandler.idp_server.parse_manage_name_id_request(query, binding)
        request = req.message

        # Do the necessary stuff
        name_id = req = self.idphandler.idp_server.ident.handle_manage_name_id_request(
            request.name_id, request.new_id, request.new_encrypted_id,
            request.terminate)

        logger.debug("New NameID: %s" % name_id)

        _resp = req = self.idphandler.idp_server.create_manage_name_id_response(request)

        # It's using SOAP binding
        hinfo = req = self.idphandler.idp_server.apply_binding(BINDING_SOAP, "%s" % _resp, "",
                                  relay_state, response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# Name ID Mapping service
# When an entity that shares an identifier for a principal with an identity
# provider wishes to obtain a name identifier for the same principal in a
# particular format or federation namespace, it can send a request to
# the identity provider using this protocol.
# ----------------------------------------------------------------------------
#Copy from pysaml example/idp2
class NIM(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, query, binding, relay_state="", mtype=None):
        req = self.idphandler.idp_server.parse_name_id_mapping_request(query, binding)
        request = req.message
        # Do the necessary stuff
        try:
            name_id = self.idphandler.idp_server.ident.handle_name_id_mapping_request(
                request.name_id, request.name_id_policy)
        except Unknown:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)
        except PolicyError:
            resp = BadRequest("Unknown entity")
            return resp(self.environ, self.start_response)

        info = self.idphandler.idp_server.response_args(request)
        _resp = self.idphandler.idp_server.create_name_id_mapping_response(name_id, **info)

        # Only SOAP
        hinfo = self.idphandler.idp_server.apply_binding(BINDING_SOAP, "%s" % _resp, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Authn query service ===
# ----------------------------------------------------------------------------
# Only SOAP binding
#Copy from pysaml example/idp2
class AQS(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, request, binding, relay_state="", mtype=None):
        logger.info("--- Authn Query Service ---")
        _req = self.idphandler.idp_server.parse_authn_query(request, binding)
        _query = _req.message

        msg = self.idphandler.idp_server.create_authn_query_response(_query.subject,
                                              _query.requested_authn_context,
                                              _query.session_index)

        logger.debug("response: %s" % msg)
        hinfo = self.idphandler.idp_server.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)

# ----------------------------------------------------------------------------
# === Attribute query service ===
# ----------------------------------------------------------------------------
# Only SOAP binding
#Copy from pysaml example/idp2
class ATTR(Service):
    def __init__(self, environ, start_response, idphandler, user=None):
        Service.__init__(self, environ, start_response, logger, user)
        self.idphandler = idphandler

    def do(self, request, binding, relay_state="", mtype=None):
        logger.info("--- Attribute Query Service ---")

        _req = self.idphandler.idp_server.parse_attribute_query(request, binding)
        _query = _req.message

        name_id = _query.subject.name_id
        uid = name_id.text
        logger.debug("Local uid: %s" % uid)
        identity = {}

        authn = self.authn_broker[self.idphandler.auth_cookie.authn_ref]
        method=None
        if authn:
            method = authn["method"]
        if method:
            identity = method.extra(self.environ, self.start_response, self.user)

        # Comes in over SOAP so only need to construct the response
        args = self.idphandler.idp_server.response_args(_query, [BINDING_SOAP])
        msg = self.idphandler.idp_server.create_attribute_response(identity,
                                            name_id=name_id, **args)

        logger.debug("response: %s" % msg)
        hinfo = self.idphandler.idp_server.apply_binding(BINDING_SOAP, "%s" % msg, "", "",
                                  response=True)

        resp = Response(hinfo["data"], headers=hinfo["headers"])
        return resp(self.environ, self.start_response)