# README

Simple Attestation client which connects to a remote tpm2d
on its TCP/IP service socket (port 9505) and asks for an attest.

## Prerequisites

The `rattestation` is automatically built together with the `cmld` in the yocto build
(`bitbake cmld`). If you want to build it on the host, the following prerequisites are required:

### Install protobuf
TODO protobuf

### Install CML common tools

TODO

### Install the IBM TSS Library

```sh
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