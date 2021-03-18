FROM debian:buster


# Dependencies

RUN apt-get update && apt-get install -y build-essential automake autoconf pkg-config
RUN apt-get update && apt-get install -y libssl-dev libtasn1-dev gnutls-dev gnutls-bin expect
RUN apt-get update && apt-get install -y git libtool tpm-tools net-tools gawk socat python3 python3-setuptools python3-pip libseccomp-dev

RUN git clone https://github.com/stefanberger/libtpms.git /opt/libtpms
RUN git clone https://github.com/stefanberger/swtpm.git /opt/swtpm

RUN cd /opt/libtpms && ./autogen.sh --with-tpm2 --with-openssl
RUN cd /opt/libtpms && make
RUN cd /opt/libtpms && make install

RUN cd /opt/swtpm && ./autogen.sh --prefix=/usr
RUN cd /opt/swtpm && make -j4
RUN cd /opt/swtpm && make install

# Provision SW TPM
RUN mkdir -p /opt/swtpmqemu
RUN ldconfig && swtpm_setup --tpm2 --tpmstate /opt/swtpmqemu/ --create-ek-cert
