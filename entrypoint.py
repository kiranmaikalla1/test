#!/usr/bin/env python

import os
import commonutil

VERSION = '1.3'
root = commonutil.get_logger()
root.info(msg='Image version={}'.format(VERSION))

def main():
    process_vault_token_generator()
    process_cacerts_loader()

def process_cacerts_loader():
    cacerts_loader = os.getenv('CACERTS_LOADER', 'true')
    root.info(msg='CA certs loader enabled : {}'.format(cacerts_loader))
    if cacerts_loader.lower() == 'true':
        import cacerts
        cacerts.main()
    else:
        root.info(msg="Skipping the CA certs loader.")

def process_vault_token_generator():
    vault_token_generator = os.getenv('VAULT_TOKEN_GENERATOR', 'true')
    root.info(msg='Vault token generator enabled : {}'.format(vault_token_generator))
    if vault_token_generator.lower() == 'true':
        import vault
        vault.main()
    else:
        root.info(msg="Skipping the vault token generator.")

if __name__ == '__main__':
    main()
