.. _apple_codesign_pkcs11:

====================
PKCS#11 (HSM) Support
====================

This project supports integration with PKCS#11-compatible Hardware
Security Modules (HSMs) and software tokens. This enables cryptographic
signing using certificates and private keys stored in secure hardware,
such as Amazon CloudHSM or Google Cloud HSM.

PKCS#11 integration is useful for organizations that require
high-assurance key management and want to keep private keys out of
software memory.

Cargo Feature
=============

PKCS#11 integration requires the optional and disabled-by-default
`pkcs11` Cargo feature to be enabled:

.. code-block:: shell

    cargo build --features pkcs11

Supported Devices
=================

Any device or software that provides a PKCS#11 interface should work. This includes:

- Amazon CloudHSM
- Google Cloud HSM
- SoftHSM (for testing)

You will need the vendor's PKCS#11 library (e.g.,
``/opt/cloudhsm/lib/libcloudhsm_pkcs11.so`` for Amazon, or the path
provided by Google for Cloud HSM).

Amazon CloudHSM Example
=======================

1. Ensure your `CloudHSM cluster is initialized <https://docs.aws.amazon.com/cloudhsm/latest/userguide/create-hsm.html>`_ and you have a user and key/certificate loaded.
2. Set up the `CloudHSM client <https://docs.aws.amazon.com/cloudhsm/latest/userguide/gs_cloudhsm_cli-install.html>`_.
3. Install the `PKCS#11 library <https://docs.aws.amazon.com/cloudhsm/latest/userguide/pkcs11-library-install.html>`_, and note the path to the PKCS#11 library (usually ``/opt/cloudhsm/lib/libcloudhsm_pkcs11.so``).
4. Sign a file using the certificate file issued by Apple:

.. code-block:: shell

    rcodesign sign \
        --pkcs11-library /opt/cloudhsm/lib/libcloudhsm_pkcs11.so \
        --pkcs11-pin <USER:PASS> \
        --pkcs11-certificate-file /path/to/cert.pem \
        --pkcs11-key-label <KEY_LABEL> \
        --code-signature-flags runtime \
        <file-to-sign>

Google Cloud HSM Example
========================

1. Set up your Google Cloud HSM and `install the PKCS#11 library <https://cloud.google.com/kms/docs/reference/pkcs11-library>`_.
2. Ensure your key and certificate are loaded and note their labels or IDs.
3. Configure the `YAML file <https://github.com/GoogleCloudPlatform/kms-integrations/blob/master/kmsp11/docs/user_guide.md#per-token-configuration>`_.
4. Set up environment variables to point to your Google credentials and configuration file. For example:

.. code-block:: shell

    export GOOGLE_APPLICATION_CREDENTIALS=/path/to/google-credentials.json
    export KMS_PKCS11_CONFIG=/path/to/config.yaml

5. Sign a file using the certificate file issued by Apple:

.. code-block:: shell

    rcodesign sign \
        --pkcs11-library /path/to/google/pkcs11.so \
        --pkcs11-pin <USER_PIN> \
        --pkcs11-certificate-file /path/to/cert.pem \
        --pkcs11-key-label <KEY_LABEL> \
        --code-signature-flags runtime \
        <file-to-sign>

Testing with SoftHSM
====================

For development and testing, you can use SoftHSM:

1. Install the required packages. On Ubuntu or Debian systems:

.. code-block:: shell

    apt update && apt install -y softhsm2 openssl opensc

2. Configure SoftHSM:

.. code-block:: shell

    # Arbitrary PIN values
    export PKCS11_SO_PIN=123456
    export PKCS11_PIN=123456

    # Initialize token
    softhsm2-util --init-token --slot 0 --label "CodeSigning" --so-pin $PKCS11_SO_PIN --pin $PKCS11_PIN

    # List tokens to verify setup
    softhsm2-util --show-slots

    # Get the slot ID of the initialized token (with label "CodeSigning")
    export SLOT_ID=$(softhsm2-util --show-slots | awk '/^Slot [0-9]/ {slot=$2} /Label:.*CodeSigning/ {print slot; exit}')
    echo "Using slot ID: $SLOT_ID"

3. Create test certificate and private key:

.. code-block:: shell

    # Arbitrary name for the key in SoftHSM
    export KEY_LABEL=mykey

    # Generate a private key
    openssl genrsa -out private_key.pem 2048

    # Create a self-signed certificate (for testing)
    openssl req -new -x509 -key private_key.pem -out test_cert.pem -days 365 -subj "/CN=Test Code Signing/O=Test Organization/C=US"

    # Convert certificate to DER format (what PKCS#11 expects)
    openssl x509 -in test_cert.pem -outform DER -out developerID_application.cer

    # Import certificate
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
        --login --pin $PKCS11_PIN \
        --slot $SLOT_ID \
        --write-object developerID_application.cer \
        --type cert \
        --label "cert"

    # Import private key
    pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
        --login --pin $PKCS11_PIN \
        --slot $SLOT_ID \
        --write-object private_key.pem \
        --type privkey \
        --label $KEY_LABEL

4. Sign a file using the test certificate:

.. code-block:: shell

    # Use rcodesign with SoftHSM's PKCS#11 library
    rcodesign sign \
        --pkcs11-library /usr/lib/softhsm/libsofthsm2.so \
        --pkcs11-certificate-file developerID_application.cer \
        --pkcs11-key-label $KEY_LABEL \
        --pkcs11-slot-id $SLOT_ID \
        --pkcs11-pin $PKCS11_PIN \
        --code-signature-flags runtime \
        <file-to-sign>

Limitations
===========

- You must know the correct label or ID for your key in the HSM, and
  have the certificate file available (unless you have imported the
  certificate into the HSM, which is uncommon).
- Some HSMs require additional configuration or environment variables.
- Only signing is supported; key generation and import must be done
  using vendor tools.
