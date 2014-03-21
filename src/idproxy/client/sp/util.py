#!/usr/bin/env python
import saml2
from saml2.extension.pefim import SPCertEnc
from saml2.md import Extensions

import xmldsig as ds
from idproxy import ServiceErrorException
from idproxy.util.saml import Service
from urlparse import parse_qs
from saml2 import BINDING_HTTP_REDIRECT, element_to_extension_element
from saml2 import ecp
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2.ecp_client import PAOS_HEADER_INFO
from saml2.httputil import geturl, parse_cookie
from saml2.httputil import Response
from saml2.httputil import ServiceError
from saml2.httputil import SeeOther
from saml2.httputil import Unauthorized
from saml2.httputil import Redirect
from saml2.httputil import NotImplemented
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import sid
from saml2.s_utils import rndstr


class EcpResponse(object):
    code = 200
    title = 'OK'

    def __init__(self, content):
        self.content = content

    #noinspection PyUnusedLocal
    def __call__(self, environ, start_response):
        start_response('%s %s' % (self.code, self.title),
                       [('Content-Type', "text/xml")])
        return [self.content]


#This class represents a cache between the SSO and ACS class.
#The SSO setup a call to a IdP and when the IdP response with a POST or REDIRECT to the ACS
#it has to remember outstanding outstanding queries to the IdP as well as relay state to perform validations.
#Each session should have it's own cache at the proxy.
class Cache(object):
    def __init__(self):
        self.outstanding_queries = {}
        self.relay_state = {}
        self.certificates = {}


class SSO(object):
    def __init__(self, sp, environ, start_response, logger, cache=None,
                 wayf=None, discosrv=None, bindings=None):
        self.sp = sp
        self.environ = environ
        self.start_response = start_response
        self.logger = logger
        self.cache = cache
        self.idp_query_param = "IdpQuery"
        self.wayf = wayf
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST,
                             BINDING_HTTP_ARTIFACT]
        logger.debug("--- SSO ---")

    def response(self, binding, http_args, do_not_start_response=False):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        elif binding == BINDING_HTTP_REDIRECT:
            for param, value in http_args["headers"]:
                if param == "Location":
                    resp = SeeOther(str(value))
                    break
            else:
                raise ServiceErrorException("Parameter error")
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])

        if do_not_start_response:
            return resp
        else:
            return resp(self.environ, self.start_response)

    def _wayf_redirect(self, came_from):
        sid_ = sid()
        self.cache.outstanding_queries[sid_] = came_from
        self.logger.debug("Redirect to WAYF function: %s" % self.wayf)
        return -1, SeeOther(headers=[('Location', "%s?%s" % (self.wayf, sid_))])

    def _pick_idp(self, came_from):
        """
        If more than one idp and if none is selected, I have to do wayf or
        disco
        """

        _cli = self.sp

        self.logger.debug("[_pick_idp] %s" % self.environ)
        if "HTTP_PAOS" in self.environ:
            if self.environ["HTTP_PAOS"] == PAOS_HEADER_INFO:
                if 'application/vnd.paos+xml' in self.environ["HTTP_ACCEPT"]:
                    # Where should I redirect the user to
                    # entityid -> the IdP to use
                    # relay_state -> when back from authentication

                    self.logger.debug("- ECP client detected -")

                    _rstate = rndstr()
                    self.cache.relay_state[_rstate] = geturl(self.environ)
                    _entityid = _cli.config.ecp_endpoint(
                        self.environ["REMOTE_ADDR"])

                    if not _entityid:
                        raise ServiceErrorException("No IdP to talk to")
                    self.logger.debug("IdP to talk to: %s" % _entityid)
                    return ecp.ecp_auth_request(_cli, _entityid, _rstate)
                else:
                    raise ServiceErrorException('Faulty Accept header')
            else:
                raise ServiceErrorException('unknown ECP version')

        # Find all IdPs
        idps = self.sp.metadata.with_descriptor("idpsso")

        idp_entity_id = None

        kaka = self.environ.get("HTTP_COOKIE", '')
        if kaka:
            try:
                (idp_entity_id, _) = parse_cookie("ve_disco", "SEED_SAW", kaka)
            except ValueError:
                pass
            except TypeError:
                pass

        # Any specific IdP specified in a query part
        query = self.environ.get("QUERY_STRING")
        if not idp_entity_id and query:
            try:
                _idp_entity_id = dict(parse_qs(query))[
                    self.idp_query_param][0]
                if _idp_entity_id in idps:
                    idp_entity_id = _idp_entity_id
            except KeyError:
                self.logger.debug("No IdP entity ID in query: %s" % query)
                pass

        if not idp_entity_id:

            if self.wayf:
                if query:
                    try:
                        wayf_selected = dict(parse_qs(query))[
                            "wayf_selected"][0]
                    except KeyError:
                        return self._wayf_redirect(came_from)
                    idp_entity_id = wayf_selected
                else:
                    return self._wayf_redirect(came_from)
            elif self.discosrv:
                if query:
                    idp_entity_id = _cli.parse_discovery_service_response(
                        query=self.environ.get("QUERY_STRING"))
                if not idp_entity_id:
                    sid_ = sid()
                    self.cache.outstanding_queries[sid_] = came_from
                    self.logger.debug("Redirect to Discovery Service function")
                    eid = _cli.config.entityid
                    ret = _cli.config.getattr("endpoints",
                                              "sp")["discovery_response"][0][0]
                    ret += "?sid=%s" % sid_
                    loc = _cli.create_discovery_service_request(
                        self.discosrv, eid, **{"return": ret})
                    return -1, SeeOther(loc)
            elif len(idps) == 1:
                # idps is a dictionary
                idp_entity_id = idps.keys()[0]
            elif not len(idps):
                raise ServiceErrorException('Misconfiguration')
            else:
                return -1, NotImplemented("No WAYF or DS present!")

        self.logger.info("Chosen IdP: '%s'" % idp_entity_id)
        return 0, idp_entity_id

    def _redirect_to_auth(self, _cli, entity_id, came_from, vorg_name="", cert_str=None, cert_key_str=None):
        try:
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            self.logger.debug("binding: %s, destination: %s" % (_binding,
                                                                destination))

            extensions = None
            if cert_key_str is not None:
                spcertenc = SPCertEnc(x509_data=ds.X509Data(x509_certificate=ds.X509Certificate(text=cert_key_str)))
                extensions = Extensions(extension_elements=[element_to_extension_element(spcertenc)])

            if _cli.authn_requests_signed:
                _sid = saml2.s_utils.sid(_cli.seed)
                req_id, msg_str = _cli.create_authn_request(destination, vorg=vorg_name, sign=_cli.authn_requests_signed,
                                                    message_id=_sid, client_crt=cert_str, extensions=extensions)
                _sid = req_id
            else:
                req_id, req = _cli.create_authn_request(destination, vorg=vorg_name, sign=False)
                msg_str = "%s" % req
                _sid = req_id

            _rstate = rndstr()
            self.cache.relay_state[_rstate] = came_from
            ht_args = _cli.apply_binding(_binding, msg_str, destination,
                                         relay_state=_rstate)

            self.logger.debug("ht_args: %s" % ht_args)
        except Exception, exc:
            self.logger.exception(exc)
            raise ServiceErrorException(
                "Failed to construct the AuthnRequest: %s" % exc)

        # remember the request
        self.cache.outstanding_queries[_sid] = came_from
        return self.response(_binding, ht_args, do_not_start_response=True)

    def do(self, cert_str=None, cert_key_str=None):
        _cli = self.sp

        # Which page was accessed to get here
        came_from = geturl(self.environ)
        self.logger.debug("[sp.challenge] RelayState >> '%s'" % came_from)

        # Am I part of a virtual organization or more than one ?
        try:
            vorg_name = _cli.vorg._name
        except AttributeError:
            vorg_name = ""

        self.logger.debug("[sp.challenge] VO: %s" % vorg_name)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(came_from)
        # Three cases: -1 something went wrong or Discovery service used
        #               0 I've got an IdP to send a request to
        #               >0 ECP in progress
        self.logger.debug("_idp_pick returned: %s" % done)
        if done == -1:
            return response(self.environ, self.start_response)
        elif done > 0:
            self.cache.outstanding_queries[done] = came_from
            return EcpResponse(response)
        else:
            entity_id = response
            # Do the AuthnRequest
            resp = self._redirect_to_auth(_cli, entity_id, came_from, vorg_name, cert_str, cert_key_str)
            return resp(self.environ, self.start_response)


# ----------------------------------------------------------------------------


# -----------------------------------------------------------------------------
#  Attribute Consuming service
# -----------------------------------------------------------------------------
class ACS(Service):
    def __init__(self, sp, authnmethod, environ, start_response, logger, cache=None, **kwargs):
        Service.__init__(self, environ, start_response, logger)
        self.sp = sp
        self.authnmethod = authnmethod
        self.environ = environ
        self.start_response = start_response
        self.outstanding_queries = cache.outstanding_queries
        self.cache = cache
        self.response = None
        self.kwargs = kwargs

    def do(self, response, binding, relay_state="", mtype="response"):
        """
        :param response: The SAML response, transport encoded
        :param binding: Which binding the query came in over
        """
        #tmp_outstanding_queries = dict(self.outstanding_queries)
        if not response:
            self.logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        try:
            self.response = self.sp.parse_authn_request_response(
                response, binding, self.outstanding_queries)
        except UnknownPrincipal, excp:
            self.logger.error("UnknownPrincipal: %s" % (excp,))
            raise ServiceErrorException("UnknownPrincipal: %s" % (excp,))
        except UnsupportedBinding, excp:
            self.logger.error("UnsupportedBinding: %s" % (excp,))
            raise ServiceErrorException("UnsupportedBinding: %s" % (excp,))
        except VerificationError, err:
            raise ServiceErrorException("Verification error: %s" % (err,))
        except Exception, err:
            raise ServiceErrorException("Other error: %s" % (err,))

        #logger.info("parsed OK")
        _resp = self.response.response

        self.logger.info("AVA: %s" % self.response.ava)

        return self.response