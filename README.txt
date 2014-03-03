===========
IdProxy
===========


IdProxy is a Op (OAuth2 and OpenId connect provider) and IdP (SAML) proxy against SAML IdP (Identi provider).

You can use this proxy for various purposes:

1) Add authentication methods to you underlying IdP, for example yubikey.
   The proxy will for example demand that the user authenticates with yubikey, before authenticating an underlying IdP.
   In that way you can upgrade multiple IdP's with at new authentication method by only allowing clients to use the
   proxy.

2) Add the OpenID connect frontend to you SAML IdP's with this proxy.

3) Anonymize. You can hide the SP:s from your IdP's and the IdP's from your SP's.

4) Same SSO token for all your underlying IdP's. All clients will only know of the SSO token from the proxy.

5) The proxy can be used in transparent mode. That implies that the certificate from the clients (SP's) is forwarded
   to the underlying IdP. In the next step can the assertion from the IdP be sent unchanged by the proxy, back to the SP.
   This is NOT to be confused with anonymizing. It is higly recommended that the assertions in this case is encrypted
   and that the public key in the SP certificate is used to encrypt keys or information.

6) SAML and OpenID Connect interface to CAS.

7) Act as a standalone OP.

8) Act as a standalone IdP.


Get up and running in a few steps.

It is higly recommended to read and understand pyoidc as well as pysaml2 before starting with IdProxy.

1) Download pysaml2 and get [..]/pysaml2/example/sp/sp.py and [..]/pysaml2/example/idp2/idp.py up and running.

2) Download pyoidc and get [..]pyoidc/oc3/oc_server.py and [..]pyoidc/rp2/rp_server.py up and running.

When your SP can talk to your IdP and your RP is talking to your OP you understand enough to proceed with the proxy.
The proxy have the same kind of configurations as the clients and servers in pysaml2 and pyoidc. It is also good
practice to know that the SP, IdP, OP and RP is working before you add a proxy in the middle. You can use any other
IdP, SP, RP or OP software as well.

3) Now get IdProxy and start by running:
    cd [..]/IdProxy
    sudo python setup.py install

4) Run the script [..]/IdProxy/certgeneration.py to generate self signed certificates or add your own valid
   certificates in the configuration later on.

5) Copy idp_conf.example to idp_conf.py. Read configuration file and follow the comments.

6) Copy op_conf.example to op_conf.py. Read configuration file and follow the comments.

7) Copy server_conf.example to server_conf.py. Read configuration file and follow the comments.

8) Copy sp_conf.example to sp_conf.py. Read configuration file and follow the comments.

9) Run [..]IdProxy/create_metadata.sh to generate metadatafiles, or use the dynmaic generated metadatafiles:
    SP : https://localhost:8999/sp_metadata
    IdP: https://localhost:8999/idp_metadata

10) Configure your SP/RP to use the proxy and configure you IdP to accepts he proxy SP. You must also configure the
    proxy SP to all the IdP's it can use. All this configuration is performed according to pyoidc and pysaml2
    documentations.


Work to be done:

1) Implement a OpenID connect and OAuth client in the proxy, to make it possible to use a OpenID connect or OAuth OP
   as backend.

2) Add a dictionary frontend to the pyYuobitool database for an easier configuration for test environments.

3) Add LDAP to the IdP part of the proxy. LDAP can already be used by the OP part.

4) More documentations, examples and comments of the code.




