#!/bin/bash

set -e

# Create test-quote
TESTQUOTE_LEN=$(($RANDOM % 1024))

echo "TESTQUOTE_LEN=${TESTQUOTE_LEN}"

dd if=/dev/random of=test-quote bs=1 count=${TESTQUOTE_LEN}
rm -f test-quote
touch test-quote

# Create test-quote digests
echo "Generating hashes"
openssl dgst -sha256 -binary test-quote > test-quote-hash
openssl dgst -sha512 -binary test-quote > test-quote-hash_sha512

# Create RSA-SSA signatures
echo "Generating RSA-SSA signatures"
openssl dgst -sha256 -sign testpki/ssig.key -out sigssa_ssacert test-quote
openssl dgst -sha256 -sign testpki/ssig_cml.key -out sigssa_psscert test-quote

openssl dgst -sha512 -sign testpki/ssig.key -out sigssa_ssacert_sha512 test-quote
openssl dgst -sha512 -sign testpki/ssig_cml.key -out sigssa_psscert_sha512 test-quote

# Create RSA-PSS signature
echo "Generating RSA-PSS signatures"
openssl dgst -sha256 -sign testpki/ssig_cml.key -out sigpss_psscert -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 test-quote
openssl dgst -sha256 -sign testpki/ssig.key -out sigpss_ssacert -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 test-quote

openssl dgst -sha512 -sign testpki/ssig_cml.key -out sigpss_psscert_sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 test-quote
openssl dgst -sha512 -sign testpki/ssig.key -out sigpss_ssacert_sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 test-quote

# Create PKCS12 tokens
echo "Generating PKCS12 tokens"
openssl pkcs12 -export -out token.p12 -inkey testpki/ssig.key -in testpki/ssig.cert -password pass:trustme
openssl pkcs12 -export -out token_pss.p12 -inkey testpki/ssig_cml.key -in testpki/ssig_cml.cert -password pass:trustme

# Create certs with appended rootca
cp testpki/ssig_rootca.cert testpki/ssig_cml_with_correct_rootca.cert
cat testpki/ssig_cml.cert >> testpki/ssig_cml_with_correct_rootca.cert

cp testpki_untrusted/ssig_rootca.cert testpki/ssig_cml_with_untrusted_rootca.cert
cat testpki/ssig_cml.cert >> testpki/ssig_cml_with_untrusted_rootca.cert

# Create cert with untrusted SubCA appended
cp testpki/ssig_cml.cert testpki/ssig_cml_with_untrusted_subca.cert
cat testpki_untrusted/ssig_subca.cert >> testpki/ssig_cml_with_untrusted_subca.cert

# Create cert file with valid SubCA and untrusted signing certificate
openssl x509 -in testpki_untrusted/ssig_cml.cert -outform pem -out testpki/valid_subca_with_untrusted_signing_cert.cert
cat testpki/ssig_subca.cert >> testpki/valid_subca_with_untrusted_signing_cert.cert

# Remove SubCA from ssig_cml.cert
openssl x509 -in testpki/ssig_cml.cert -outform pem -out testpki/ssig_cml_without_subca.cert

# Append duplicate cert chain to ssig_cml.cert
cp testpki/ssig_cml.cert testpki/ssig_cml_duplicate_chains.cert
cat testpki_untrusted/ssig_cml.cert >> testpki/ssig_cml_duplicate_chains.cert


# Create self-signed certificate
openssl req -batch -config openssl-selfsigned.cnf -newkey rsa:4096 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -x509 -days 100 -passout pass:test1234 -keyout selfsigned.key -out selfsigned.cert

# Append selfsigned cert to ssig cml certs
cp testpki/ssig_cml.cert testpki/ssig_cml_with_selfsigned.cert
cat selfsigned.cert >> testpki/ssig_cml_with_selfsigned.cert

cp testpki_untrusted/ssig_cml.cert testpki_untrusted/ssig_cml_with_selfsigned.cert
cat selfsigned.cert >> testpki_untrusted/ssig_cml_with_selfsigned.cert

# Complete untrusted chain in ssig cert
cp testpki_untrusted/ssig_rootca.cert testpki_untrusted/ssig_cml_complete_chain.cert
cat testpki_untrusted/ssig_cml.cert >> testpki_untrusted/ssig_cml_complete_chain.cert



# Create additional certificates
SSIG_ROOTCA_INDEX_FILE="testpki/ssig_rootca_index.txt"
PASS_IN=""

TRUSTME_TEST_PASSWD_PKI="test1234"
export TRUSTME_TEST_PASSWD_PKI

PASS_IN="-passin env:TRUSTME_TEST_PASSWD_PKI"
PASS_OUT="-passout env:TRUSTME_TEST_PASSWD_PKI"

error_check(){
if [ "$1" != "0" ]; then
  echo "Error: $2"
  cleanup
  exit 1
fi
}


# ssig cert signed with trusted root CA
echo "Create software signing (CML) CSR"
openssl req -batch -config openssl-ssig-cml-rootsigned.cnf -newkey rsa-pss -pkeyopt rsa_keygen_bits:4096 ${PASS_IN} ${PASS_OUT} -out testpki/ssig_cml_rootsigned.csr -outform PEM
error_check $? "Failed to create software signing (CML) CSR"

echo "Sign software signing CSR with ssig root CA (CML) certificate"
touch ${SSIG_ROOTCA_INDEX_FILE}
openssl ca -notext -create_serial -batch -config openssl-ssig-rootca.cnf -policy signing_policy -extensions signing_req_CA ${PASS_IN} -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out testpki/ssig_cml_rootsigned.cert -infiles testpki/ssig_cml_rootsigned.csr
error_check $? "Failed to sign software signing (CML) CSR with ssig sub CA (CML) certificate"

echo "Verify newly created ssig (CML) certificate"
openssl verify -CAfile testpki/ssig_rootca.cert testpki/ssig_cml_rootsigned.cert
error_check $? "Failed to verify newly signed (CML) ssig certificate"

# ssig cert signed with untrusted root CA
echo "Create untrusted software signing (CML) CSR"
openssl req -batch -config openssl-ssig-cml-rootsigned.cnf -newkey rsa-pss -pkeyopt rsa_keygen_bits:4096 ${PASS_IN} ${PASS_OUT} -out testpki_untrusted/ssig_cml_rootsigned.csr -outform PEM
error_check $? "Failed to create software signing (CML) CSR"

echo "Sign software signing CSR with untrusted ssig root CA (CML) certificate"
touch ${SSIG_ROOTCA_INDEX_FILE}
openssl ca -notext -create_serial -batch -config openssl-ssig-rootca-untrusted.cnf -policy signing_policy -extensions signing_req_CA ${PASS_IN} -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out testpki_untrusted/ssig_cml_rootsigned.cert -infiles testpki_untrusted/ssig_cml_rootsigned.csr
error_check $? "Failed to sign software signing (CML) CSR with ssig sub CA (CML) certificate"

echo "Verify newly created ssig (CML) certificate"
openssl verify -CAfile testpki_untrusted/ssig_rootca.cert testpki_untrusted/ssig_cml_rootsigned.cert
error_check $? "Failed to verify newly signed (CML) ssig certificate"

# cleanup unneeded files
for i in pem csr attr old; do
	rm testpki/*.${i}
	rm testpki_untrusted/*.${i}
done
rm testpki_untrusted/ssig_cml_rootsigned.key
rm selfsigned.key
