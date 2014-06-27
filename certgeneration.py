#!/usr/bin/env python
# -*- coding: utf-8 -*-
from saml2.cert import OpenSSLWrapper

def generateCert(cert_info=None, gen_jwks_cert=True):
    cert_info_ca = {
        "cn": "localhost",
        "country_code": "se",
        "state": "ac",
        "city": "Test",
        "organization": "Test org",
        "organization_unit": "Testers"
    }

    if cert_info is not None:
        cert_info_ca = cert_info

    osw = OpenSSLWrapper()

    sn = 1

    try:
        sn = osw.read_str_from_file("sn.txt")
        if len(sn) > 0:
            sn = int(sn)
            sn += 1
        else:
            sn = 1
    except:
        pass

    ca_cert1, ca_key1 = osw.create_certificate(cert_info_ca, request=False, write_to_file=True,
                                               cert_dir="./httpsCert", sn=sn)

    sn += 1

    ca_cert2, ca_key2 = osw.create_certificate(cert_info_ca, request=False, write_to_file=True,
                                               cert_dir="./idp_cert", sn=sn)

    sn += 1

    ca_cert3, ca_key3 = osw.create_certificate(cert_info_ca, request=False, write_to_file=True,
                                               cert_dir="./sp_cert", sn=sn)

    sn += 1

    ca_cert4 = None
    if gen_jwks_cert:
        ca_cert4, ca_key4 = osw.create_certificate(cert_info_ca, request=False, write_to_file=True,
                                                cert_dir="./opKeys", sn=sn, key_length=2048)


    sn += 1

    osw.write_str_to_file("sn.txt", str(sn))

    return sn, ca_cert4
