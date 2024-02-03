<!-- vim: set ft=markdown : -->


# Parquet Modular Encryption demo

!["If you secure everything with a key, how are you going to protect the key?" "With another key"
😐](.assets/more-keys-1.jpg)

🔼 [source](https://stephenroughley.com/2019/06/09/concepts-of-compliant-data-encryption/)

## Introduction

### Summary

🔽 [source](https://github.com/apache/parquet-format/blob/master/Encryption.md)

Parquet files containing sensitive information can be protected by the modular encryption mechanism
that encrypts and authenticates the file data and metadata - while allowing for a regular Parquet
functionality (columnar projection, predicate pushdown, encoding and compression).

#### Problem statement

Existing data protection solutions (such as flat encryption of files, in-storage encryption, or
use of an encrypting storage client) can be applied to Parquet files, but have various security or
performance issues. An encryption mechanism, integrated in the Parquet format, allows for an optimal
combination of data security, processing speed and encryption granularity.

#### Goals

1. Protect Parquet data and metadata by encryption, while enabling selective reads (columnar
   projection, predicate push-down).

1. Implement "client-side" encryption/decryption (storage client). The storage server must not see
   plaintext data, metadata or encryption keys.

1. Leverage authenticated encryption that allows clients to check integrity of the retrieved data
   \- making sure the file (or file parts) have not been replaced with a wrong version, or tampered
   with otherwise.

1. Enable different encryption keys for different columns and for the footer.

1. Allow for partial encryption - encrypt only column(s) with sensitive data.

1. Work with all compression and encoding mechanisms supported in Parquet.

1. Support multiple encryption algorithms, to account for different security and performance
   requirements.

1. Enable two modes for metadata protection -

    * full protection of file metadata

    * partial protection of file metadata that allows legacy readers to access unencrypted columns
      in an encrypted file.

1. Minimize overhead of encryption - in terms of size of encrypted files, and throughput of
   write/read operations.

### How it works

The Parquet writer generates a DEK (data encryption key) for each plaintext chunk to be encrypted,
encrypts the plaintext chunk, then sends the DEK to the KMS (key management service) to be wrapped
by the chosen KEK (key encryption key). The KMS returns the wrapped DEK to the Parquet writer, which
stores the wrapped DEK alongside the corresponding ciphertext chunk.

To read a ciphertext chunk, the Parquet reader sends the corresponding wrapped DEK to the KMS, which
unwraps it and returns the DEK to the Parquet reader. The reader decrypts the ciphertext chunk with
the DEK.

## Prerequisites

* Python 3.12. Prepare the environment by running the following code:

    ``` shell
    python3.12 -m venv -- ./venv
    source -- ./venv/bin/activate
    python -m pip install --upgrade -- pip setuptools wheel
    python -m pip install --no-deps -r requirements.txt
    python -m pip check
    ```

## Example

Launch the KMS (key management service).

``` shell
./kms_server.py
```

Explore the KMS' [Swagger UI](http://localhost:8001/docs). Try POSTing the JSON payload

``` json
{
  "key": "rlCLtKLrH/b9GZbuZaneQB6yU6vp8tlC1R2LINMYYrM="
}
```

to one of the wrap endpoints and then try unwrapping the result via the corresponding unwrap
endpoint at various privilege levels. To set a privilege level, click the "Authorize" button and set
the value of the `x-api-key` request header to `INTERNAL`, `CONFIDENTIAL` or `RESTRICTED`. `PUBLIC`
does not require the `x-api-key` request header. (plaintext < `PUBLIC` < `INTERNAL` < `CONFIDENTIAL`
< `RESTRICTED`)

Write an encrypted Parquet dataset with columns of varying privilege levels.

``` shell
./write_encrypted_parquet.py
```

Read the entire dataset.

``` shell
./read_encrypted_parquet.py
```

Edit `read_encrypted_parquet.py` and experiment with different combinations of `KMS_ACCESS_TOKEN`
and `COLUMNS` to project. The default is:

``` python
KMS_ACCESS_TOKEN = WrappingKeyId.RESTRICTED
COLUMNS = [
    "id",  # minimum required privilege: none (plaintext)
    "date_of_birth",  # minimum required privilege: INTERNAL
    "first_name",  # minimum required privilege: CONFIDENTIAL
    "last_name",  # minimum required privilege: CONFIDENTIAL
    "social_security_number",  # minimum required privilege: RESTRICTED
]
```

`RESTRICTED` is the highest privilege level and may decrypt all columns, which is why projecting all
columns earlier was successful.

Note that `id` is the only plaintext column, and no access token is required to project it (i.e.
`KMS_ACCESS_TOKEN = None`).

## Final comments

Please note that in reality KEKs should be narrowly scoped (e.g. project-specific), periodically
rotated, and gated behind IAM (Identity and Access Management) more secure than static API keys.

Production-grade KMS include [Hashicorp
Vault](https://developer.hashicorp.com/vault/docs/secrets/key-management), [AWS
KMS](https://docs.aws.amazon.com/kms/), [GCP Cloud KMS](https://cloud.google.com/kms/docs) and
[Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/).

## References

* [Concepts of Compliant Data
  Encryption](https://stephenroughley.com/2019/06/09/concepts-of-compliant-data-encryption/)

* [Parquet Modular Encryption](https://github.com/apache/parquet-format/blob/master/Encryption.md)

* [Parquet Modular Encryption (Apache
  Arrow)](https://arrow.apache.org/docs/python/parquet.html#parquet-modular-encryption-columnar-encryption)

* [Test Driving Parquet
  Encryption](https://medium.com/@tomersolomon/test-driving-parquet-encryption-3d5319f5bc22)

* [One Stone, Three Birds: Finer-Grained Encryption with Apache Parquet @ Large
  Scale](https://doi.org/10.1109/BigData55660.2022.10020987)
