.. _index:

IdProxy
=======

IdProxy is an Op (OAuth2 and OpenId connect provider) and IdP (SAML) proxy against SAML IdP (Identity provider).

.. toctree::
   :maxdepth: 2

   install
   setup

Usage
=====

You can use this proxy for various purposes:

* Add authentication methods to your underlying IdP, for example yubikey. The proxy will for example demand that the user authenticates with yubikey, before authenticating an underlying IdP. In that way you can upgrade multiple IdP's with a new authentication method by only allowing clients to use the proxy.
* Add the OpenID connect frontend to you SAML IdP's with this proxy.
* Anonymize. You can hide the SP:s from your IdP's and the IdP's from your SP's.
* Same SSO token for all your underlying IdP's. All clients will only know of the SSO token from the proxy.
* The proxy can be used in transparent mode. That implies that the certificate from the clients (SP's) is forwarded to the underlying IdP. In the next step can the assertion from the IdP be sent unchanged by the proxy, back to the SP. This is NOT to be confused with anonymizing. It is higly recommended that the assertions in this case is encrypted and that the public key in the SP certificate is used to encrypt keys or information. The proxy can either use the certificate in the extension element SPCertEncType or the certificate sent with the signature. It is recommeded to use SPCertEncType to transfer the certificate and let the proxy handle the signatures. If the signature certificate are to be sent from the calling SP to the underlying IdP, no signature can performed on the authn request made by the proxy to the underlying IdP.
* SAML and OpenID Connect interface to CAS.
* Act as a standalone OP. A bit wierd for a proxy, but you can do it.
* Act as a standalone IdP. A bit wierd for a proxy, but you can do it. :)

