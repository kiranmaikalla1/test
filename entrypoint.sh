#!/bin/sh

echo " ___ ___                __  __        _______         __                       _______                                    __                ";
echo "|   |   |.---.-..--.--.|  ||  |_     |_     _|.-----.|  |--..-----..-----.    |     __|.-----..-----..-----..----..---.-.|  |_ .-----..----.";
echo "|   |   ||  _  ||  |  ||  ||   _|      |   |  |  _  ||    < |  -__||     |    |    |  ||  -__||     ||  -__||   _||  _  ||   _||  _  ||   _|";
echo " \_____/ |___._||_____||__||____|      |___|  |_____||__|__||_____||__|__|    |_______||_____||__|__||_____||__|  |___._||____||_____||__|  ";
echo "                                                                                                                                            ";

echo "Verifying that all required environment variables are set.."

if [ -z "${VAULT_ADDR}" ]; then
        echo "ERROR! VAULT_ADDR environment variable is not set"
        exit 77
elif [ -z "${VAULT_ROLE}" ]; then
        echo "ERROR! VAULT_ROLE environemnt variable is not set"
        exit 78
elif [ -z "${VAULT_K8S_MOUNT_PATH}" ]; then
	echo "ERROR! VAULT_K8S_MOUNT_PATH environment variable is not set"
	exit 79
fi

if [ -z "${TOKEN_PATH}" ]; then
	echo "WARN: TOKEN_PATH environment variable is not set, setting to default value (/var/secrets)"
	TOKEN_PATH=/var/secrets
fi

echo \{\"jwt\": \"$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\"\, \"role\": \"$VAULT_ROLE\"\} > /tmp/data.json

VAULT_LOGIN_RESPONSE_CODE=$(curl -s -X POST --data @/tmp/data.json ${VAULT_ADDR}/v1/auth/${VAULT_K8S_MOUNT_PATH}/login -o ${TOKEN_PATH}/k8s_login.json --write-out %{http_code})

if [ "${VAULT_LOGIN_RESPONSE_CODE}" -ne 200 ] ; then
        echo "Vault login failed with error code ${VAULT_LOGIN_RESPONSE_CODE}"
        cat ${TOKEN_PATH}/k8s_login.json
        exit 99
else
	echo "Vault login succeeded. Access token will be written to the designated path"
fi

cat ${TOKEN_PATH}/k8s_login.json | jq -r '.auth.client_token' > ${TOKEN_PATH}/vault_access_token