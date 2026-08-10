.. _apple_codesign_aws_kms:

=====================
Signing with AWS KMS
=====================

``rcodesign`` supports signing with asymmetric keys held in
`AWS KMS <https://docs.aws.amazon.com/kms/>`_. The private key never leaves
KMS: each signing operation calls the KMS ``Sign`` API.

AWS KMS support requires the ``aws-kms`` Cargo feature to be enabled:

.. code-block:: bash

    cargo build --features aws-kms

Credentials
===========

AWS credentials are resolved through the standard AWS SDK default provider
chain: environment variables, shared config/credentials files, IMDS, and web
identity federation (OIDC) via ``AWS_WEB_IDENTITY_TOKEN_FILE`` /
``AWS_ROLE_ARN``. The latter is particularly useful in CI environments
(GitHub Actions, Buildkite, GitLab CI) which can mint OIDC identity tokens,
allowing code signing without any long-lived secrets.

The principal needs ``kms:GetPublicKey`` and ``kms:Sign`` permissions on
the signing key.

Code signing
============

Create an asymmetric KMS key with usage ``SIGN_VERIFY`` and spec ``RSA_2048``
(Developer ID certificates use RSA keys), issue a CSR from it, and have Apple
issue a certificate for the key. Then:

.. code-block:: bash

    rcodesign sign \
        --aws-kms-key arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb \
        --aws-kms-certificate-file developer_id.pem \
        path/to/input path/to/output

The certificate's public key is validated against the KMS key's public key
(via ``GetPublicKey``) before any signing occurs.

ECDSA P-256 (``ECC_NIST_P256``) keys are also supported. RSA signatures use
``RSASSA_PKCS1_V1_5_SHA_256``; ECDSA signatures use ``ECDSA_SHA_256``.

The corresponding config file section is:

.. code-block:: toml

    [sign.aws_kms]
    key_id = "arn:aws:kms:us-east-1:123456789012:key/aaaa-bbbb"
    certificate_file = "developer_id.pem"
    region = "us-east-1"

Notarization
============

The App Store Connect API private key (an ECDSA P-256 key used to sign
``ES256`` JWTs) can also be held in KMS. Import the ``.p8`` key material
into a KMS ``ECC_NIST_P256`` signing key (or create a fresh key and register
its public key with Apple), then encode a unified API key file that
references KMS instead of embedding the private key:

.. code-block:: bash

    rcodesign encode-app-store-connect-api-key \
        --aws-kms-key arn:aws:kms:us-east-1:123456789012:key/cccc-dddd \
        -o api_key.json \
        <issuer-id> <key-id>

The resulting ``api_key.json`` contains no secret material and can be
committed to a repository. ``rcodesign notary-submit --api-key-file
api_key.json ...`` works as usual, minting JWTs via KMS.
