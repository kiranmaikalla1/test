#!/usr/bin/env python

import os
import requests
import sys
import json
import subprocess
import commonutil
import logging
import socket
logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)

print """
 ,-----.   ,---.    ,-----. ,------. ,------.  ,--------.  ,---.     ,--.     ,-----.    ,---.   ,------.   ,------. ,------.
'  .--./  /  O  \  '  .--./ |  .---' |  .--. ' '--.  .--' '   .-'    |  |    '  .-.  '  /  O  \  |  .-.  \  |  .---' |  .--. '
|  |     |  .-.  | |  |     |  `--,  |  '--'.'    |  |    `.  `-.    |  |    |  | |  | |  .-.  | |  |  \  : |  `--,  |  '--'.'
'  '--'\ |  | |  | '  '--'\ |  `---. |  |\  \     |  |    .-'    |   |  '--. '  '-'  ' |  | |  | |  '--'  / |  `---. |  |\  \
 `-----' `--' `--'  `-----' `------' `--' '--'    `--'    `-----'    `-----'  `-----'  `--' `--' `-------'  `------' `--' '--'
"""

root = commonutil.get_logger()
expected_vars = ['VAULT_ADDR','VAULT_TOKEN']

commonutil.verify_expected_vars(expected_vars)

CACERTS_PATH = os.getenv('CACERTS_PATH', '/var/secrets')
CACERTS_FILE = '{}/cacerts'.format(CACERTS_PATH)
CACERTS_URL = os.getenv('CACERTS_URL', 'https://nexusmirror.tpp.tsysecom.com/repository/buildscripts/repos/buildscripts/raw/certs/cacerts-tsys')
CERTS_VAULT_PATH = os.getenv('CERTS_VAULT_PATH', 'secret/digitalInnovations/app/tools/cacerts')
REGION = os.getenv('REGION', 'qa')

VAULT_ADDR = os.getenv('VAULT_ADDR')

logging.debug('Started debuging hostname resolution for vault url')

VAULT_URL=commonutil.hostname_resolution(VAULT_ADDR)
print(VAULT_URL)

# ================== END GLOBAL ================== #

def download_base_cacerts():
    session = commonutil.retry_session(retries=5)
    response = session.get(CACERTS_URL, verify=False)
    # If the response was successful, no Exception will be raised
    response.raise_for_status()

    with open(CACERTS_FILE, 'w') as tf:
        tf.write(response.content)

def load_certs():
    vault_token = os.getenv('VAULT_TOKEN')
    url=VAULT_URL
    vault_certs_path = "/usr/local/certs/{0}/cer.pem".format(REGION)

    vault_url = "{0}/v1/{1}".format(url, CERTS_VAULT_PATH)
    root.info(msg="Vault url: {}".format(vault_url))
    headers_content = {'Content-Type': 'application/json', 'X-Vault-Token': vault_token}

    session = commonutil.retry_session(retries=5)
    response = session.get(vault_url, headers=headers_content, verify=vault_certs_path)

    if response.status_code != 200:
        root.critical(msg="Gettting certs from vault failed with error {0} ({1}, {2})".format(response.status_code,
                                                                                response.reason,
                                                                                response.text.rstrip()))
    else:
        json_response = response.json()
        certificates = json_response['data']

        if certificates is None:
            root.critical(msg="No certificates found in the vault {0}".format(vault_url))
        else:
            for key,value in certificates.items():
                pem_data = value['CERTIFICATE']
                alias_name = value['ALIAS']
                cert_file_path = CACERTS_PATH + '/' + key +'.cer'
                with open(cert_file_path, 'w') as tf:
                    tf.write(pem_data)
                delete_if_certs_exists(alias_name)
                import_certs(alias_name,cert_file_path)

def delete_if_certs_exists(alias_name):
    try:
        list_output  = subprocess.check_output('keytool -list -storepass changeit -noprompt -alias %s -keystore %s'%(alias_name,CACERTS_FILE), stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
        root.info(msg="Keytool list results for alias name {0} : {1}".format(alias_name,list_output))
        root.info(msg="Certificate already exists in cacerts for alias name {}. Initiating the delete process before import".format(alias_name))
        delete_certs(alias_name)
    except subprocess.CalledProcessError as nonzero:
        root.critical(msg="Exception in Keytool list results for alias name {0} : {1}".format(alias_name,nonzero.output))
        if "does not exist" in nonzero.output:
            root.info(msg="Certificate does not exists in cacerts for alias name {}. Skipping the delete process before import".format(alias_name))
        else:
            sys.exit(-1)

def delete_certs(alias_name):
    try:
        delete_output  = subprocess.check_output('keytool -delete -storepass changeit -noprompt -alias %s -keystore %s'%(alias_name,CACERTS_FILE), stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
        root.info(msg="Successfully deleted the certificate with alias name {0} : {1}".format(alias_name,delete_output))
    except subprocess.CalledProcessError as nonzero:
        root.critical(msg="Exception in Keytool delete for alias name {0} : {1}".format(alias_name,nonzero.output))
        sys.exit(-1)

def import_certs(alias_name,cert_file_path):
    try:
        import_output  = subprocess.check_output('keytool -importcert -storepass changeit -noprompt -alias %s -file %s -keystore %s'%(alias_name,cert_file_path,CACERTS_FILE), stderr=subprocess.STDOUT, shell=True, universal_newlines=True)
        root.info(msg="Successfully imported the certificate with alias name {0} : {1}".format(alias_name,import_output))
    except subprocess.CalledProcessError as nonzero:
        root.critical(msg="Exception in Keytool import for alias name {0} : {1}".format(alias_name,nonzero.output))
        sys.exit(-1)

def main():
    download_base_cacerts()
    load_certs()
