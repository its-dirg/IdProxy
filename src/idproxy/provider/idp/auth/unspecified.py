__author__ = 'haho0032'
import logging

from idproxy.provider.idp.auth.util import IdPAuthentication


logger = logging.getLogger("pyOpSamlProxy.provider.idp.unspecified")


class UnspecifiedAuth(IdPAuthentication):
    pass