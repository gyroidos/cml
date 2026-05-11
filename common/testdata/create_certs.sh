#!/bin/bash

SCRIPT_DIR="$(dirname ${BASH_SOURCE[0]})"
SCRIPT_DIR="$(readlink -f ${SCRIPT_DIR})"

if [ -z "$1" ];then
	echo "No workdir specified, using $(pwd)"
	WORKDIR="$(pwd)"
else
	echo "Using specified workdir: $1"
	WORKDIR="$(readlink -e $1)"
fi

if ! [ -d "${SCRIPT_DIR}" ];then
	echo "ERROR: SCRIPT_DIR not a directory, exiting..."
	exit 1
fi

if ! [ -d "${WORKDIR}" ];then
	echo "ERROR: WORKDIR not a directory, exiting..."
	exit 1
fi
	
echo "SCRIPT_DIR: ${SCRIPT_DIR}"
echo "WORKDIR: ${WORKDIR}"

cd ${WORKDIR}

CERT_CONF_DIR="${SCRIPT_DIR}/cert_confs"

mkdir -p "${WORKDIR}"

SSIG_SUBCA_CML_CONFIG="${SCRIPT_DIR}/cert_confs/openssl-ssig-subca-cml.cnf"
SSIG_SUBCA_CONFIG="${SCRIPT_DIR}/cert_confs/openssl-ssig-subca.cnf"

SSIG_ROOTCA_CERT="${WORKDIR}/ssig_rootca.cert"
SSIG_SUBCA_CML_CSR="${WORKDIR}/ssig_subca_cml.csr"
SSIG_SUBCA_CML_CERT="${WORKDIR}/ssig_subca_cml.cert"
SSIG_CML_SINGLE_CSR="${WORKDIR}/ssig_cml_single.cert"
SSIG_CML_SINGLE_CERT="${WORKDIR}/ssig_cml_single.cert"
SSIG_CML_CERT="${WORKDIR}/ssig_cml.cert"

SSIG_SUBCA_CSR="${WORKDIR}/ssig_subca.csr"
SSIG_SUBCA_CERT="${WORKDIR}/ssig_subca.cert"
SSIG_SINGLE_CSR="${WORKDIR}/ssig_single.cert"
SSIG_SINGLE_CERT="${WORKDIR}/ssig_single.cert"
SSIG_CERT="${WORKDIR}/ssig.cert"


# Certificate parameters
DAYS_VALID="365"
KEY_SIZE="4096"


PASS_IN="-passin env:GYROIDOS_TEST_PASSWD_PKI"
PASS_OUT="-passout env:GYROIDOS_TEST_PASSWD_PKI"



# Create additional certificates
SSIG_ROOTCA_INDEX_FILE="ssig_rootca_index.txt"
SSIG_SUBCA_CML_INDEX_FILE="ssig_subca_cml_index.txt"
SSIG_SUBCA_INDEX_FILE="ssig_subca_index.txt"

export GYROIDOS_TEST_PASSWD_PKI

error_check(){
if [ "$1" != "0" ]; then
  echo "Error: $2"
  exit 1
fi
}

# Create rootca
echo "Create self-signed ssig root CA certificate using ${CERT_CONF_DIR}/openssl-ssig-rootca.cnf"
openssl req -batch -x509 -config "${CERT_CONF_DIR}/openssl-ssig-rootca.cnf" -newkey rsa:${KEY_SIZE} -days ${DAYS_VALID} ${PASS_IN} ${PASS_OUT} -out ${SSIG_ROOTCA_CERT} -outform PEM 
error_check $? "Failed to create self signed ssig root CA certificate"

# Create ssig_subca_cml.cert
echo "Create ssig sub CA (CML) CSR using ${CERT_CONF_DIR}/openssl-ssig-subca.cnf"
openssl req -verbose -batch -config ${CERT_CONF_DIR}/openssl-ssig-subca-cml.cnf -newkey rsa-pss -pkeyopt rsa_keygen_bits:${KEY_SIZE} ${PASS_IN} ${PASS_OUT} -out ${SSIG_SUBCA_CML_CSR} -outform PEM 
error_check $? "Failed to create ssig sub CA (CML) CSR"

echo "Sign ssig sub CA (CML) CSR with ssig root CA"
touch ${SSIG_ROOTCA_INDEX_FILE}
openssl ca -notext -create_serial -batch -config ${CERT_CONF_DIR}/openssl-ssig-rootca.cnf -policy signing_policy -extensions signing_req_CA ${PASS_IN} -out ${SSIG_SUBCA_CML_CERT} -infiles ${SSIG_SUBCA_CML_CSR}
error_check $? "Failed to sign ssig sub CA CSR (CML) with ssig root CA certificate"

echo "Verify newly created ssig sub CA (CML) certificate"
openssl verify -CAfile ${SSIG_ROOTCA_CERT} ${SSIG_SUBCA_CML_CERT}
error_check $? "Failed to verify newly signed ssig sub CA (CML) certificate"


# Create ssig_cml.cert
echo "Create software signing (CML) CSR"
openssl req -batch -config ${CERT_CONF_DIR}/openssl-ssig-cml.cnf -newkey rsa-pss -pkeyopt rsa_keygen_bits:${KEY_SIZE} ${PASS_IN} ${PASS_OUT} -out ${SSIG_CML_SINGLE_CSR} -outform PEM 
error_check $? "Failed to create software signing (CML) CSR"

echo "Sign software signing CSR with ssig sub CA (CML) certificate"
touch ${SSIG_SUBCA_CML_INDEX_FILE}
openssl ca -notext -create_serial -batch -config ${SSIG_SUBCA_CML_CONFIG} -policy signing_policy -extensions signing_req ${PASS_IN} -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out ${SSIG_CML_SINGLE_CERT} -infiles ${SSIG_CML_SINGLE_CSR}
error_check $? "Failed to sign software signing (CML) CSR with ssig sub CA (CML) certificate"

echo "Verify newly created ssig (CML) certificate"
openssl verify -CAfile ${SSIG_ROOTCA_CERT} -untrusted ${SSIG_SUBCA_CML_CERT} ${SSIG_CML_SINGLE_CERT}
error_check $? "Failed to verify newly signed (CML) ssig certificate"

echo "Concatenate ssig CA (CML) chain to ssig.cert"
cat "${SSIG_SUBCA_CML_CERT}" >> "${SSIG_CML_CERT}"
cat "${SSIG_CML_SINGLE_CERT}" >> "${SSIG_CML_CERT}"



# Create ssig_subca.cert
echo "Create ssig sub CA CSR using ${CERT_CONF_DIR}/openssl-ssig-subca.cnf"
openssl req -verbose -batch -config ${CERT_CONF_DIR}/openssl-ssig-subca.cnf -newkey rsa:${KEY_SIZE} ${PASS_IN} ${PASS_OUT} -out ${SSIG_SUBCA_CSR} -outform PEM 
error_check $? "Failed to create ssig sub CA CSR"

echo "Sign ssig sub CA CSR with ssig root CA"
touch ${SSIG_ROOTCA_INDEX_FILE}
openssl ca -notext -create_serial -batch -config ${CERT_CONF_DIR}/openssl-ssig-rootca.cnf -policy signing_policy -extensions signing_req_CA ${PASS_IN} -out ${SSIG_SUBCA_CERT} -infiles ${SSIG_SUBCA_CSR}
error_check $? "Failed to sign ssig sub CA CSR with ssig root CA certificate"

echo "Verify newly created ssig sub CA certificate"
openssl verify -CAfile ${SSIG_ROOTCA_CERT} ${SSIG_SUBCA_CERT}
error_check $? "Failed to verify newly signed ssig sub CA certificate"


# Create ssig.cert
echo "Create software signing CSR"
openssl req -batch -config ${CERT_CONF_DIR}/openssl-ssig.cnf -newkey rsa:${KEY_SIZE} ${PASS_IN} ${PASS_OUT} -out ${SSIG_SINGLE_CSR} -outform PEM 
error_check $? "Failed to create software signing CSR"

echo "Sign software signing CSR with ssig sub CA certificate"
touch ${SSIG_SUBCA_INDEX_FILE}
openssl ca -notext -create_serial -batch -config ${SSIG_SUBCA_CONFIG} -policy signing_policy -extensions signing_req ${PASS_IN} -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -out ${SSIG_SINGLE_CERT} -infiles ${SSIG_SINGLE_CSR}
error_check $? "Failed to sign software signing CSR with ssig sub CA certificate"

echo "Verify newly created ssig certificate"
openssl verify -CAfile ${SSIG_ROOTCA_CERT} -untrusted ${SSIG_SUBCA_CERT} ${SSIG_SINGLE_CERT}
error_check $? "Failed to verify newly signed ssig certificate"

echo "Concatenate ssig CA chain to ssig.cert"
cat "${SSIG_SUBCA_CERT}" >> "${SSIG_CERT}"
cat "${SSIG_SINGLE_CERT}" >> "${SSIG_CERT}"

# cleanup unneeded files
for i in pem csr attr old; do
	rm *.${i}
done
