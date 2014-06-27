#!/usr/bin/env python
# -*- coding: utf-8 -*-

from base64 import b64encode
import json

from Crypto.PublicKey import RSA
from Crypto.Util.asn1 import DerSequence
from OpenSSL import crypto

from saml2.cert import OpenSSLWrapper

def generatePublicKey(cert_file):
    osw = OpenSSLWrapper()
    cert_str = osw.read_str_from_file(cert_file)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_str)
    pub_key = cert.get_pubkey()
    src = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pub_key)
    pub_der = DerSequence()
    pub_der.decode(src)
    pub_key_rsa = RSA.construct((long(pub_der._seq[1]), long(pub_der._seq[2])))
    pemSeq = DerSequence()
    pemSeq[:] = [pub_key_rsa.key.n, pub_key_rsa.key.e]
    s = pub_key_str = b64encode(pemSeq.encode())
    pem_src = '-----BEGIN RSA PUBLIC KEY-----\n'
    while True:
        pem_src += s[:64] + '\n'
        s = s[64:]
        if s == '':
            break
    pem_src += '-----END RSA PUBLIC KEY-----'

    jwks = {"keys": [{"use": "enc", "e": "AQAB", "kty": "RSA", "n": pub_key_str},
                     {"use": "sig", "e": "AQAB", "kty": "RSA", "n": pub_key_str}]}

    jwks_str = json.dumps(jwks)
    osw.write_str_to_file("./static/jwks.json", jwks_str)