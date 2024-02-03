#!/usr/bin/env python
# vim: set ft=python :

import contextlib
import datetime
import shutil
from pathlib import Path

import pyarrow as pa
import pyarrow.dataset as ds
import pyarrow.parquet as pq
import pyarrow.parquet.encryption as pe

from kms_client import KmsClient, WrappingKeyId

KMS_INSTANCE_URL = "http://localhost:8001"
KMS_ACCESS_TOKEN = None
PATH = Path("dataset")


def write_to_dataset(table, root_path, **kwargs):
    default_kwargs = {
        "compression": "zstd",
        "compression_level": 19,
        "data_page_version": "2.0",
        "existing_data_behavior": "error",
    }
    pq.write_to_dataset(table, root_path, **{**default_kwargs, **kwargs})


def main():
    schema = pa.schema(
        [
            pa.field("id", pa.int64(), nullable=False),
            pa.field("date_of_birth", pa.date32()),
            pa.field("first_name", pa.string()),
            pa.field("last_name", pa.string()),
            pa.field("social_security_number", pa.string()),
        ]
    )

    table = pa.Table.from_pylist(
        [
            {
                "id": 1,
                "date_of_birth": datetime.date(1988, 2, 17),
                "first_name": "Mike",
                "last_name": "Truk",
                "social_security_number": "123-45-6789",
            },
            {
                "id": 2,
                "date_of_birth": datetime.date(1989, 2, 6),
                "first_name": "Rey",
                "last_name": "McSriff",
                "social_security_number": "234-56-7890",
            },
            {
                "id": 3,
                "date_of_birth": datetime.date(2020, 1, 25),
                "first_name": "Todd",
                "last_name": "Bonzalez",
                "social_security_number": "345-67-8901",
            },
        ],
        schema=schema,
    )

    encryption_config = ds.ParquetEncryptionConfig(
        crypto_factory=pe.CryptoFactory(KmsClient),
        kms_connection_config=pe.KmsConnectionConfig(
            kms_instance_url=KMS_INSTANCE_URL,
            key_access_token=KMS_ACCESS_TOKEN,
        ),
        encryption_config=pe.EncryptionConfiguration(
            cache_lifetime=datetime.timedelta(minutes=1),
            column_keys={
                WrappingKeyId.INTERNAL: ["date_of_birth"],
                WrappingKeyId.CONFIDENTIAL: ["first_name", "last_name"],
                WrappingKeyId.RESTRICTED: ["social_security_number"],
            },
            data_key_length_bits=256,
            double_wrapping=True,
            encryption_algorithm="AES_GCM_V1",
            footer_key=WrappingKeyId.PUBLIC,
            internal_key_material=True,
            plaintext_footer=True,
        ),
    )

    with contextlib.suppress(FileNotFoundError):
        shutil.rmtree(PATH)
    write_to_dataset(table, PATH, encryption_config=encryption_config)


if __name__ == "__main__":
    main()
