#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import shutil
from certgeneration import generateCert
from saml2.cert import OpenSSLWrapper

generate_cert_str = "    \"only_use_keys_in_metadata\": False,\n" \
                        "    \"cert_handler_extra_class\": None,\n" \
                        "    \"generate_cert_info\": {\n" \
                        "        \"cn\": BASE,\n" \
                        "        \"country_code\": \"COUNTRY_CODE\",\n" \
                        "        \"state\": \"STATE_REPLACE\",\n" \
                        "        \"city\": \"CITY_REPLACE\",\n" \
                        "        \"organization\": \"ORG_REPLACE\",\n" \
                        "        \"organization_unit\": \"UNIT_REPLACE\"},\n" \
                        "    \"tmp_key_file\": WORKING_DIR + \"sp_cert/tmp_mykey.pem\",\n" \
                        "    \"tmp_cert_file\": WORKING_DIR + \"sp_cert/tmp_mycert.pem\",\n"

generate_root_cert = False
root_cert_info_ca = None

def write_str_to_file(file, str_data):
    f = open(file, "wt")
    f.write(str_data)
    f.close()


def read_str_from_file(file):
    f = open(file)
    str_data = f.read()
    f.close()
    return str_data

folders = ['httpsCert', 'idp_cert', 'opKeys', 'sp_cert', 'static']

for folder in folders:
    if not os.path.exists(folder):
        os.makedirs(folder)

raw_input("This script will help you to perform the basic configurations needed to get up and running. (Press enter)")


shutil.copy2('idp_conf.example', 'test_idp_conf.py')
shutil.copy2('sp_conf.example', 'test_sp_conf.py')
shutil.copy2('op_conf.example', 'test_op_conf.py')
shutil.copy2('server_conf.example', 'test_server_conf.py')

server_str = read_str_from_file('test_server_conf.py')
op_str = read_str_from_file('test_op_conf.py')
idp_str = read_str_from_file('test_idp_conf.py')
sp_str = read_str_from_file('test_sp_conf.py')

port = raw_input("Port for the server:")
try:
    (int(port))
except Exception:
    print "Not a port, using default value 8999."
    port = "8999"
server_str = server_str.replace("PORT = 8999", "PORT = " + str(port))
_true = raw_input("Write True to activate HTTPS:")
_true = "True" == _true
server_str = server_str.replace("HTTPS = True", "HTTPS = " + str(_true))
host = raw_input("Your host (use localhost for testing):")
if host is None or len(host) == 0:
    host = "localhost"
    print "Host is set to localhost."
server_str = server_str.replace("HOST=\"localhost\"", "HOST = \"" + str(host) + "\"")

proxy = None
password = None
while (proxy != "Yes") and (proxy != "No"):
    proxy = raw_input("Type Yes to setup a proxy or No(default) to the OP and Idp with only password verification:")
    if (proxy != "Yes") and (proxy != "No"):
        print "Please type Yes or No..."
if proxy == "Yes":
    proxy = True
else:
    proxy = False
    password = True

yes = raw_input("Type Yes(Y) for a quick setup of a onetime certificate based proxy.")
quicksetup_cert_anonym_proxy = (yes.lower() == "yes" or yes.lower() == "y")

if proxy:
    while (password != "Yes") and (password != "No"):
        password = raw_input("Type Yes to add password verification for using the proxy, otherwise No:")
        print "(The proxy also support CAS, Yubikey, LDAP etc... but the quick setup do NOT!)"
        if (password != "Yes") and (password != "No"):
            print "Please type Yes or No..."
    if password == "Yes":
        password = True
    else:
        password = False

if proxy:
    op_str = op_str.replace("#    \"SAML\": {\"ACR\": \"SAML\", \"WEIGHT\": 3, \"URL\": ISSUER, \"USER_INFO\": \"SAML\"},",
                   "    \"SAML\": {\"ACR\": \"SAML\", \"WEIGHT\": 3, \"URL\": ISSUER, \"USER_INFO\": \"SAML\"},")
    idp_str = idp_str.replace("    #\"SAML\": {\"ACR\": authn_context_class_ref(UNSPECIFIED), \"WEIGHT\": 3, \"URL\": BASE, \"USER_INFO\": \"SAML\"},",
                              "    \"SAML\": {\"ACR\": authn_context_class_ref(UNSPECIFIED), \"WEIGHT\": 3, \"URL\": BASE, \"USER_INFO\": \"SAML\"},")

    idp_meta = raw_input("Url (must begin with http) or path to metadata file contaning all IdP's that should be behind the proxy:")
    url = False
    try:
        if idp_meta[:4] == "http":
            url = True
    except Exception:
        pass
    if url:
        sp_str = sp_str.replace("\"metadata\": {\"local\": [\"[..]/idp.xml\"]},",
                                  "\"metadata\": {\"remote\": [{ \"url\":\"" + idp_meta + "\", \"cert\": None}],},")
    else:
        sp_str = sp_str.replace("\"metadata\": {\"local\": [\"[..]/idp.xml\"]},",
                                  "\"metadata\": {\"local\": [\"" + idp_meta + "\"],},")

    discovery = None
    while (discovery != "Yes") and (discovery != "No"):
        discovery = raw_input("Do you have multiple IdP's behind the proxy, answer Yes or No:")
        print "The proxy supports WAYF but not the quick setup."
        if (discovery != "Yes") and (discovery != "No"):
            print "Please type Yes or No..."
    if discovery == "Yes":
        discovery = True
    else:
        discovery = False

    if discovery:
        discovery_server = raw_input("Url to the discovery server:")
        sp_str = sp_str.replace("DISCOSRV = None", "DISCOSRV = \"" + str(discovery_server) + "\"")

    yes = raw_input("Type Yes(Y) to sign authn requests (all other answers is considered no):")
    if (yes.lower() == "yes" or yes.lower() == "y"):
        sp_str = sp_str.replace("#\"authn_requests_signed\": \"true\",",
                                "\"authn_requests_signed\": \"true\",")

    if not quicksetup_cert_anonym_proxy:
        yes = raw_input("Type Yes(Y) to verify that assertions are signed (all other answers is considered no):")
    if yes.lower() == "yes" or yes.lower() == "y" or quicksetup_cert_anonym_proxy:
        sp_str = sp_str.replace("#\"want_assertions_signed\": \"true\",",
                                "\"want_assertions_signed\": \"true\",")

    if not quicksetup_cert_anonym_proxy:
        yes = raw_input("Type Yes(Y) to verify certificates from an IdP (all other answers is considered no):")
    if yes.lower() == "yes" or yes.lower() == "y" or quicksetup_cert_anonym_proxy:
        sp_str = sp_str.replace("#\"validate_certificate\": True,",
                                "\"validate_certificate\": True,")

    if not quicksetup_cert_anonym_proxy:
        yes = raw_input("Type Yes(Y) to generate new certificates for each authn request (all other answers is considered no):")
    else:
        print "Type the information that will be included on the generated the certificates."
    if yes.lower() == "yes" or yes.lower() == "y" or quicksetup_cert_anonym_proxy:
        tmp_generate_cert_str = generate_cert_str
        country_code = raw_input("Country code(2 letters):")
        state = raw_input("State:")
        city = raw_input("City:")
        org = raw_input("Organisation:")
        unit = raw_input("Organisation unit:")
        tmp_generate_cert_str = tmp_generate_cert_str.replace("COUNTRY_CODE", state)
        tmp_generate_cert_str = tmp_generate_cert_str.replace("STATE_REPLACE", state)
        tmp_generate_cert_str = tmp_generate_cert_str.replace("CITY_REPLACE", city)
        tmp_generate_cert_str = tmp_generate_cert_str.replace("ORG_REPLACE", org)
        tmp_generate_cert_str = tmp_generate_cert_str.replace("UNIT_REPLACE", unit)
        sp_str = sp_str.replace("#CERT_GENERATION", tmp_generate_cert_str)
        sp_str = sp_str.replace("sp_cert/localhost.key", "root_cert/localhost.ca.key")
        sp_str = sp_str.replace("sp_cert/localhost.crt", "root_cert/localhost.ca.crt")
        generate_root_cert = True

if not password:
    op_str = op_str.replace("    \"PASSWORD\": {\"ACR\": \"PASSWORD\", \"WEIGHT\": 1, \"URL\": ISSUER, \"USER_INFO\": \"SIMPLE\"},",
                   "#    \"PASSWORD\": {\"ACR\": \"PASSWORD\", \"WEIGHT\": 1, \"URL\": ISSUER, \"USER_INFO\": \"SIMPLE\"},")
    idp_str = idp_str.replace("\"PASSWORD\": {\"ACR\": authn_context_class_ref(PASSWORD), \"WEIGHT\": 1, \"URL\": BASE, \"USER_INFO\": \"SIMPLE\"},",
                              "#\"PASSWORD\": {\"ACR\": authn_context_class_ref(PASSWORD), \"WEIGHT\": 1, \"URL\": BASE, \"USER_INFO\": \"SIMPLE\"},")

sp_meta = raw_input("Url (must begin with http) or path to metadata file contaning all SP's that should make use of the proxy:")
url = False
try:
    if sp_meta[:4] == "http":
        url = True
except Exception:
    pass
if url:
    idp_str = idp_str.replace("\"metadata\": {\"local\": [\"[..]/sp.xml\"],},",
                              "\"metadata\": {\"remote\": [{ \"url\":\"" + sp_meta + "\", \"cert\": None}],},")
else:
    idp_str = idp_str.replace("\"metadata\": {\"local\": [\"[..]/sp.xml\"],},",
                              "\"metadata\": {\"local\": [\"" + sp_meta + "\"],},")


if password:
    print "Connect to the proxy with your SP or RP and login with the user test1 and password qwerty."

write_str_to_file('test_server_conf.py', server_str)
write_str_to_file('test_op_conf.py', op_str)
write_str_to_file('test_idp_conf.py', idp_str)
write_str_to_file('test_sp_conf.py', sp_str)


print "Type the information for all server certificates; https, sp and idp."
country_code = raw_input("Country code(2 letters):")
state = raw_input("State:")
city = raw_input("City:")
org = raw_input("Organisation:")
unit = raw_input("Organisation unit:")
server_cert_info_ca = {
    "cn": host,
    "country_code": country_code,
    "state": state,
    "city": city,
    "organization": org,
    "organization_unit": unit
}

sn = generateCert(server_cert_info_ca)

if generate_root_cert:
    if not os.path.exists("root_cert"):
        os.makedirs("root_cert")
        print "Type the information for the root certificate."
        country_code = raw_input("Country code(2 letters):")
        state = raw_input("State:")
        city = raw_input("City:")
        org = raw_input("Organisation:")
        unit = raw_input("Organisation unit:")
        root_cert_info_ca = {
            "cn": host,
            "country_code": country_code,
            "state": state,
            "city": city,
            "organization": org,
            "organization_unit": unit
        }
        osw = OpenSSLWrapper()
        ca_cert1, ca_key1 = osw.create_certificate(root_cert_info_ca, request=False, write_to_file=True,
                                               cert_dir="/localhost.ca", sn=sn)