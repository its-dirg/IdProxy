Student verifier
================

The proxy can be configured to verify if someone is an active student by using a SAML federation.

The proxy will front a OpenID provider and use a SAML IdP or federation as backend.

This example will only describe the parts that will add the student verification parts.

In the file sp_conf.py, or whatever you call your local version of sp_conf.example, add the following settings::

    #Contains all valid attributes and valid values for that attribute.
    VALID_ATTRIBUTE_RESPONSE = {
        "eduPersonAffiliation": ["student"]
    }

    #Contains all attributes that will be returned.
    ATTRIBUTE_WHITELIST = [
        "eduPersonScopedAffiliation"
    ]


The backend Service Provider will now only allow users that get student as response in the eduPersonAffiliation
attribute to be authenticated. Furthermore will only the attribute eduPersonScopedAffiliation be sent back to the client
as a response.

This works off course both for OP and SAML frontends, so turn on/off the frontends that are needed.