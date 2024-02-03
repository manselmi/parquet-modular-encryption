# vim: set ft=python :

import base64
import operator
import os
import ssl
from enum import StrEnum

import pyarrow.parquet.encryption as pe
from httpx import Client, Headers


class WrappingKeyId(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class KmsClient(pe.KmsClient):
    BASE_PATH = "/api/v1/"
    WRAP_ENDPOINT = "wrap/"
    UNWRAP_ENDPOINT = "unwrap/"
    TOKEN_HEADER = "x-api-key"

    def __init__(self, kms_connection_config):
        super().__init__()
        headers = Headers()
        if (token := kms_connection_config.key_access_token) is not None:
            headers[KmsClient.TOKEN_HEADER] = token
        self._client = Client(
            base_url=kms_connection_config.kms_instance_url + KmsClient.BASE_PATH,
            event_hooks={"response": [operator.methodcaller("raise_for_status")]},
            headers=headers,
            verify=ssl.create_default_context(cafile=os.environ.get("TLS_CA_BUNDLE_PEM")),
        )

    def __del__(self):
        self._client.close()

    def wrap_key(self, key_bytes, master_key_identifier):
        r = self._client.post(
            KmsClient.WRAP_ENDPOINT + master_key_identifier,
            json={"key": base64.b64encode(key_bytes).decode()},
        )
        return r.json()["key"]

    def unwrap_key(self, wrapped_key, master_key_identifier):
        r = self._client.post(
            KmsClient.UNWRAP_ENDPOINT + master_key_identifier,
            json={"key": wrapped_key},
        )
        return base64.b64decode(r.json()["key"])
