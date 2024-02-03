#!/usr/bin/env python
# vim: set ft=python :

import datetime
from pathlib import Path

import pyarrow.dataset as ds
import pyarrow.parquet.encryption as pe

from kms_client import KmsClient, WrappingKeyId

PATH = Path("dataset")
KMS_INSTANCE_URL = "http://localhost:8001"
# KMS_ACCESS_TOKEN = None
# KMS_ACCESS_TOKEN = WrappingKeyId.INTERNAL
# KMS_ACCESS_TOKEN = WrappingKeyId.CONFIDENTIAL
KMS_ACCESS_TOKEN = WrappingKeyId.RESTRICTED
COLUMNS = [
    "id",  # minimum required privilege: none (plaintext)
    "date_of_birth",  # minimum required privilege: INTERNAL
    "first_name",  # minimum required privilege: CONFIDENTIAL
    "last_name",  # minimum required privilege: CONFIDENTIAL
    "social_security_number",  # minimum required privilege: RESTRICTED
]


def main():
    format_ = ds.ParquetFileFormat(
        default_fragment_scan_options=ds.ParquetFragmentScanOptions(
            decryption_config=ds.ParquetDecryptionConfig(
                pe.CryptoFactory(KmsClient),
                pe.KmsConnectionConfig(
                    kms_instance_url=KMS_INSTANCE_URL,
                    key_access_token=KMS_ACCESS_TOKEN,
                ),
                pe.DecryptionConfiguration(cache_lifetime=datetime.timedelta(minutes=1)),
            )
        )
    )

    dataset = ds.dataset(PATH, format=format_)

    table = dataset.scanner(columns=COLUMNS).to_table()
    for row in table.to_pylist():
        print(row)


if __name__ == "__main__":
    main()
