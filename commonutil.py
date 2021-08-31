#!/usr/bin/env python

import logging
import sys
import os
import requests
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
import socket

root = logging.getLogger()
root.setLevel(logging.DEBUG)

ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
root.addHandler(ch)

def get_logger():        
    return root

def retry_session(retries, session=None, backoff_factor=0.3, status_forcelist=(500, 502, 503, 504)):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        method_whitelist=['HEAD', 'TRACE', 'GET', 'PUT', 'OPTIONS', 'DELETE', 'POST'],
        raise_on_status=False
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def verify_expected_vars(expected_vars):
    root.info(msg='Verifying all expected variables exist: {}'.format(expected_vars))
    for v in expected_vars:
        if not os.getenv(v):
            root.critical(msg="{} environment variable is NOT SET!".format(v))
            exit(77)
        else:
            root.debug(msg='{} environment variable is set with value {}'.format(v, os.getenv(v)))


def hostname_resolution(VAULT_ADDR):
    VAULT_RESOLV=VAULT_ADDR.split("//")[1].split(":")[0]
    logging.info(VAULT_RESOLV)

    print('Trying to resolve {}:'.format(VAULT_RESOLV))
    try:
        VAULT_IP=socket.gethostbyname(VAULT_RESOLV)
        logging.debug(VAULT_IP)
        print('Successful in getting vault ip DNS is working fine:',VAULT_IP)
        print("Url passed will be: ",VAULT_ADDR)
        return VAULT_ADDR
    
    except socket.gaierror as error:
        logging.critical("Unable to get VAULT_IP from vault address, Hardcoded ip will be used")
        print("There was error in resolving {}".format(VAULT_RESOLV))
        print(error)
        logging.info("Trying with Hardcoded ip")
        if 'edc' in VAULT_ADDR:
            VAULT_IP = 'https://10.123.82.190:8300'
            return VAULT_IP
        elif 'ukedc' in VAULT_ADDR:
            VAULT_IP = 'https://10.113.188.253:8300'
            return VAULT_IP
        elif 'ndc' in VAULT_ADDR:
            VAULT_IP = 'https://10.121.83.103:8300'
            return VAULT_IP
        elif 'ukndc' in VAULT_ADDR:
            VAULT_IP = 'https://10.113.186.253:8300'
            return VAULT_IP
    except:
        logging.critical("Unable to reach vault, please check vault if vault is up:")
