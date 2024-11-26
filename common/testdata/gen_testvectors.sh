#!/bin/bash

#set -e

PKI_DIR_TRUSTED="testpki"
PKI_DIR_UNTRUSTED="testpki_untrusted"

export TRUSTME_TEST_PASSWD_PKI="test1234"

########## Tokens and Certificates ##########
# Create PKCS12 tokens
echo "Generating PKCS12 tokens"

mkdir -p "${PKI_DIR_TRUSTED}"
mkdir -p "${PKI_DIR_UNTRUSTED}"

bash create_certs.sh "${PKI_DIR_TRUSTED}"
bash create_certs.sh "${PKI_DIR_UNTRUSTED}"

echo "Creating PKCS#11 token using ${PKI_DIR_TRUSTED}/ssig_cml.key and ${PKI_DIR_TRUSTED}/ssig_cml.cert"
TRUSTME_TEST_PASSWD_PKI="test1234" openssl pkcs12 -export -out token_pss.p12 -inkey ${PKI_DIR_TRUSTED}/ssig_cml.key -in ${PKI_DIR_TRUSTED}/ssig_cml.cert -passin env:TRUSTME_TEST_PASSWD_PKI -password pass:trustme

echo "Creating PKCS#11 token using ${PKI_DIR_TRUSTED}/ssig.key and ${PKI_DIR_TRUSTED}/ssig.cert"
TRUSTME_TEST_PASSWD_PKI="test1234" openssl pkcs12 -export -out token.p12 -inkey ${PKI_DIR_TRUSTED}/ssig.key -in ${PKI_DIR_TRUSTED}/ssig.cert -passin env:TRUSTME_TEST_PASSWD_PKI -password pass:trustme

########## Combined cert file ##########
cp testpki_untrusted/ssig_rootca.cert untrusted_chain_including_rootca.cert
cat testpki_untrusted/ssig_cml.cert >> untrusted_chain_including_rootca.cert



########## Digests and Signatures ##########
# Create test-quote
TESTQUOTE_LEN=$(($RANDOM % 1024))
echo "TESTQUOTE_LEN=${TESTQUOTE_LEN}"

dd if=/dev/random of=test-quote bs=1 count=${TESTQUOTE_LEN}

# Create test-quote digests
echo "Generating hashes"
openssl dgst -sha256 -binary test-quote > test-quote-hash_sha256
openssl dgst -sha512 -binary test-quote > test-quote-hash_sha512

# Create Signatures
COMMON_PKEYOPTS_PSS="-pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest"

echo "Creating sigpss_psscert_sha256"
openssl pkeyutl -sign -digest SHA256 -pkeyopt rsa_mgf1_md:SHA256 $COMMON_PKEYOPTS_PSS -inkey testpki/ssig_cml.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote -out sigpss_psscert_sha256
echo "Creating sigpss_psscert_sha512"
openssl pkeyutl -sign -digest SHA512 -pkeyopt rsa_mgf1_md:SHA512 $COMMON_PKEYOPTS_PSS -inkey testpki/ssig_cml.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote -out sigpss_psscert_sha512

echo "Creating sigssa_ssacert_sha256"
openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pkcs1 -digest SHA-256 -inkey testpki/ssig.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote -out sigssa_ssacert_sha256

echo "Creating sigssa_ssacert_sha512"
openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pkcs1 -digest SHA-512 -inkey testpki/ssig.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote -out sigssa_ssacert_sha512


# Verify Signatures
echo "Verifying sigpss_psscert_sha256"
openssl pkeyutl -verify -digest SHA256 $COMMON_PKEYOPTS_PSS -pkeyopt rsa_mgf1_md:SHA256 -sigfile sigpss_psscert_sha256 -certin -inkey testpki/ssig_cml_single.cert -rawin -in test-quote
echo "Verifying sigpss_psscert_sha512"
openssl pkeyutl -verify -digest SHA512 $COMMON_PKEYOPTS_PSS -pkeyopt rsa_mgf1_md:SHA512 -sigfile sigpss_psscert_sha512 -certin -inkey testpki/ssig_cml_single.cert -rawin -in test-quote

echo "Verifying sigssa_ssacert_sha256"
openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pkcs1 -digest SHA-256 -sigfile  sigssa_ssacert_sha256 -inkey testpki/ssig.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote

echo "Verifying sigssa_ssacert_sha512"
openssl pkeyutl -verify -pkeyopt rsa_padding_mode:pkcs1 -digest SHA-512 -sigfile  sigssa_ssacert_sha512 -inkey testpki/ssig.key -passin env:TRUSTME_TEST_PASSWD_PKI -rawin -in test-quote
