# Using TPM emulation in KVM for CML

This short howto describes howto build and setup
the [swtpm] (https://github.com/stefanberger/swtpm) as TPM 2.0 emulation in KVM for testing the CML.


## Install dependencies for swtpm and libtpms

Dependencies on a debian testing system:
```
apt-get install build-essential automake autoconf
apt-get install libssl-dev libtasn1-dev gnutls-dev gnutls-bin expect
```
list of libtpms/INSTALL
(Ubuntu)
- automake
- autoconf
- libtool
- make
- gcc
- libc-dev
- libssl-dev

Full list of swtpm/INSTALL:
- automake
- autoconf
- bash
- coreutils
- expect
- libtool
- sed
- libtpms
- libtpms-devel
- fuse
- fuse-devel
- glib2
- glib2-devel
- net-tools
- python3
- python3-twisted
- selinux-policy-devel
- trousers
- tpm-tools
- gnutls
- gnutls-devel
- libtasn1
- libtasn1-tools
- libtasn1-devel
- rpm-build (to build RPMs)


## Install and built swtpm/libtpms
> See also: https://github.com/stefanberger/libtpms/blob/master/INSTALL

We need TPM 2.0 emulation only, thus I provide a patch for
swtpm which allows to build without tpm-tools and trousers.

```
git clone https://github.com/stefanberger/libtpms.git
git clone https://github.com/quitschbo/swtpm.git
```

```
cd libtpms
./autogen.sh --with-tpm2 --with-openssl
make
sudo make install
```
swtpm_setup defaults will not work out of the box in `/usr/local`

```
cd swtpm
./autogen.sh --prefix=/usr
make -j4
sudo make install
```

## Run TPM 2.0 emulator

> See also https://github.com/qemu/qemu/blob/master/docs/specs/tpm.txt

### Provision TPM / create certificate for EK (only once needed)
For testing purpose, we can use the default provisioning
configuration of swtpm. It is installed in `/etc/swtpm-setup.conf`
and uses `swtpm-localca.conf` and `swtpm-localca.options`.
Thus, a default CA will be crated in `/var/lib/swtpm-localca/`
by the following command and the EK stored in the internal state
of the _virtual_ TPM.

```
mkdir /tmp/swtpmqemu
sudo swtpm_setup --tpm2 --tpmstate /tmp/swtpmqemu/ --create-ek-cert
```
If you do not want to run the provisioning as root, you
have to provide own configs located in user writable location
and specify `--config` (See `man swtpm_setup`).

### run the emulator
```
swtpm socket --tpmstate dir=/tmp/swtpmqemu --tpm2 \
	--ctrl type=unixio,path=/tmp/swtpmqemu/swtpm-sock
```
### run qemu/kvm
Following example runs a yocto build of CML using the tpm emulator
```
kvm -m 2048 -cpu host --bios OVMF.fd -serial mon:stdio \
	-kernel	out-yocto/tmp/deploy/images/intel-corei7-64/bzImage-initramfs-intel-corei7-64.bin.signed \ 
	-drive format=raw,file=out-yocto/tmp/deploy/images/intel-corei7-64/trustx-cml-userdata-intel-corei7-64.ext4 \
	-chardev socket,id=chrtpm,path=/tmp/swtpmqemu/swtpm-sock \
	-tpmdev emulator,id=tpm0,chardev=chrtpm \
	-device tpm-tis,tpmdev=tpm0
```
