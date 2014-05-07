from uuid import uuid4
from idproxy.client.sp.handler import SpHandler
from idproxy.provider.idp.handler import IdPHandler
import server_conf

__author__ = 'haho0032'
#Imports within the project
from dirg_util.log import create_logger
from dirg_util.http_util import HttpHandler, BadRequest
from dirg_util.session import Session
from idproxy.provider.op.handler import OpHandler
#Imports within DIG

#External imports
import importlib
import argparse
from cherrypy import wsgiserver
from cherrypy.wsgiserver import ssl_pyopenssl
from beaker.middleware import SessionMiddleware
from mako.lookup import TemplateLookup
from saml2.s_utils import exception_trace

#Lookup for all mako templates.
LOOKUP = TemplateLookup(directories=['mako/templates', "/opt/dirg/dirg-util/mako/templates", 'mako/htdocs'],
                        module_directory='mako/modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

class start_response_intercept(object):

    def __init__(self, start_response):
        self.start_response = start_response

    def __call__(self, status, response_headers, exc_info=None):
        self.status = status
        self.response_headers = response_headers
        self.exc_info = exc_info
        self.start_response(status, response_headers, exc_info=None)



def application(environ, start_response):
    """
    WSGI application. Handles all requests.
    :param environ: WSGI enviroment.
    :param start_response: WSGI start response.
    :return: Depends on the request. Always a WSGI response where start_response first have to be initialized.
    """
    try:
        start_response = start_response_intercept(start_response)
        session = Session(environ)

        http_helper = HttpHandler(environ, start_response, session, logger)
        path = http_helper.path()

        environ = sphandler.verify_sp_user_validity(session, environ, path)
        http_helper.log_request()
        response = None
        if server_conf.OP_FRONTEND and ophandler.verify_provider_requests(path):
            response = ophandler.handle_provider_requests(environ, start_response, path, session)
        if server_conf.IDP_FRONTEND and idphandler.verify_provider_requests(path, environ):
            response = idphandler.handle_provider_requests(environ, start_response, path)
        elif sphandler.verify_sp_requests(path):
            response = sphandler.handle_sp_requests(environ, start_response, path, session)
        elif http_helper.verify_static(path):
            return http_helper.handle_static(path)

        if response is None:
            response = http_helper.http404()

        http_helper.log_response(response)
        #Catch all unauthorized attemps and present a better web page.
        if start_response.status[0:3] == "401":
            mte = LOOKUP.get_template("unauthorized.mako")
            message = None
            if len(response) == 1:
                message = str(response[0])
            if message is None or len(message.strip()) == 0:
                message = "You are not authorized!"
            argv = {
                "message": message,
            }
            return [mte.render(**argv)]
        return response
    except Exception, excp:
        urn = uuid4().urn
        logger.error("uuid: " + str(urn) + str(exception_trace(excp)))
        argv = {
            "log_id": str(urn),
        }
        mte = LOOKUP.get_template("bad_request.mako")
        resp = BadRequest(mte.render(**argv))
        return resp(environ, start_response)

if __name__ == '__main__':
    #This is equal to a main function in other languages. Handles all setup and starts the server.

    #Read arguments.
    parser = argparse.ArgumentParser()
    parser.add_argument('-va', dest='valid', default="4",
                        help="How long, in days, the metadata is valid from the time of creation")
    parser.add_argument('-c', dest='cert', help='certificate')
    parser.add_argument('-isp', dest='id_sp',
                        help="The ID of the entities descriptor in the metadata for the SP")
    parser.add_argument('-idp', dest='id_idp',
                        help="The ID of the entities descriptor in the metadata for the IdP")
    parser.add_argument('-k', dest='keyfile',
                        help="A file with a key to sign the metadata with")
    parser.add_argument('-nsp', dest='name_sp')
    parser.add_argument('-nidp', dest='name_idp')
    parser.add_argument('-s', dest='sign', action='store_true',
                        help="sign the metadata")
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-t', dest='test', action='store_true')
    parser.add_argument(dest="config")
    parser.add_argument(dest="idpconfig")
    parser.add_argument(dest="spconf")
    args = parser.parse_args()

    #Application in debug mode if true.
    debug = False
    test = False
    if args.debug:
        debug = True
        #Application in test mode if true.
    if args.test:
        test = True

    global logger
    logger = create_logger(server_conf.LOG_FILE)

    global sphandler
    sphandler = SpHandler(logger, args)

    global ophandler
    if server_conf.OP_FRONTEND:
        config = importlib.import_module(args.config)
        ophandler = OpHandler(logger, config, LOOKUP, sphandler, test, debug)
        sphandler.ophandler = ophandler
    else:
        ophandler = None
        sphandler.ophandler = None

    global idphandler
    if server_conf.IDP_FRONTEND:
        idphandler = IdPHandler(args, LOOKUP, sphandler, server_conf.ISSUER)
    else:
        idphandler = None


    global SRV
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', server_conf.PORT), SessionMiddleware(application,
                                                                                    server_conf.SESSION_OPTS))
    SRV.stats['Enabled'] = True
    #SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', config.PORT), application)
    if server_conf.HTTPS:
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(server_conf.SERVER_CERT, server_conf.SERVER_KEY,
                                                         server_conf.CERT_CHAIN)
    logger.info("Server starting")
    print "Server listening on port: %s" % server_conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
