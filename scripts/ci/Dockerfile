FROM debian:bullseye


# Essentials
RUN apt-get update && apt-get install -y gawk wget git-core diffstat unzip texinfo gcc-multilib build-essential chrpath socat cpio python3 python3-pip python3-pexpect xz-utils debianutils iputils-ping libsdl1.2-dev xterm lsb-release libprotobuf-c1 libprotobuf-c-dev protobuf-compiler protobuf-c-compiler autoconf libtool libtool-bin re2c check rsync lz4 zstd


# CI
RUN apt-get install -y libssl-dev libcap-dev libselinux-dev apt-transport-https
#
# clang-9 toolchain for debian stretch
# maybe even 11 would be good
RUN echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main" >> /etc/apt/sources.list
RUN echo "deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-10 main" >> /etc/apt/sources.list
RUN wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -
RUN apt-get update && apt-get install -y clang-13 clang-tools-13 clang-13-doc libclang-common-13-dev libclang-13-dev libclang1-13 clang-format-13 python3-clang-13 clangd-13 lld-13 lldb-13 libfuzzer-13-dev
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-13 100
RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-13 100
RUN update-alternatives --install /usr/bin/clangd clangd /usr/bin/clangd-13 100
RUN update-alternatives --install /usr/bin/clang-format clang-format /usr/bin/clang-format-13 100

# Image signing
RUN apt-get update && apt-get install -y python3-protobuf

# Qemu
RUN apt-get update && apt-get install -y qemu-kvm ovmf

# Bootable medium
RUN apt-get update && apt-get install -y util-linux btrfs-progs gdisk parted

RUN apt-get update && apt-get install -y libssl-dev libtar-dev screen locales ca-certificates gosu locales
RUN dpkg-reconfigure locales
RUN echo "LC_ALL=en_US.UTF-8" >> /etc/environment
RUN echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen
RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf
RUN locale-gen en_US.UTF-8

RUN apt-get update && apt-get install -y kmod procps curl

# trusted-connector build dependencies
# for new yarn based build of trusted-connector core compartment

RUN apt-get install -y apt-utils

# optee python dependings
RUN apt-get update && apt-get install -y python3-cryptography

RUN echo "deb http://ftp.de.debian.org/debian bullseye-backports main contrib non-free" >> /etc/apt/sources.list

RUN apt-get -y update && apt-get -y install -t bullseye-backports linux-image-amd64

# set image label
ARG CML_BUILDER=jenkins

LABEL "com.gyroidos.builder"="${lbl}"

# protobuf-c-text library
ADD https://github.com/gyroidos/external_protobuf-c-text/archive/refs/heads/master.zip /opt/external_protobuf-c-text-master.zip

RUN cd /opt && unzip external_protobuf-c-text-master.zip

RUN cd /opt/external_protobuf-c-text-master && ./autogen.sh && ./configure && make && make install

# Set workdir
WORKDIR "/opt/ws-yocto/"

#COPY ./entrypoint.sh /usr/local/bin/entrypoint.sh

#ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

