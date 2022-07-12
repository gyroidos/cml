# README

Simple Attestation client which connects to a remote tpm2d
on its TCP/IP service socket (port 9505) and asks for an attest.

## Prerequisites

The `rattestation` is automatically built together with the `cmld` in the yocto build
(`bitbake cmld`). If you want to build it on the host, the following prerequisites are required:

### Install protobuf

```sh
git clone https://github.com/gyroidos/external_protobuf-c-text.git
cd external_protobuf-c-text/
git submodule update --init --recursive

autoreconf -f -i
./configure --enable-static=yes
make
make install
```

### Install CML common tools

TODO

### Install the IBM TSS Library

```sh
# TODO check for newest version
mkdir -p ibmtss1.6.0
cd ibmtss1.6.0
wget https://deac-ams.dl.sourceforge.net/project/ibmtpm20tss/ibmtss1.6.0.tar.gz
tar xvzf ibmtss1.6.0.tar.gz
rm ibmtss1.6.0.tar.gz

export LD_LIBRARY_PATH=/usr/local/lib

autoreconf -i
./configure --disable-hwtpm
make clean
make
make install
```


## Compile

```sh
make
```

## Run

By default, `rattestation` uses 127.0.0.1 as the remote host and `rattestation.conf` as the
configuration file (an example is in this folder). If you want to specify a different host and
config_file, you can put these as additional arguments:

```sh
./attestation [remote_host config_file]
```