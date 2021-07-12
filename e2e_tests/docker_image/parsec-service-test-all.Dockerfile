# Copyright 2021 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0
FROM ubuntu:18.04

# The specific version of libraries used in this Dockerfile should not change without having
# carefully checked that this is not breaking stability.
# See https://github.com/parallaxsecond/parsec/issues/397
# and https://parallaxsecond.github.io/parsec-book/parsec_service/stability.html

ENV PKG_CONFIG_PATH /usr/local/lib/pkgconfig

RUN apt update
RUN apt install -y autoconf-archive libcmocka0 libcmocka-dev procps
RUN apt install -y iproute2 build-essential git pkg-config gcc libtool automake libssl-dev uthash-dev doxygen libjson-c-dev
RUN apt install -y --fix-missing wget python3 cmake clang
RUN apt install -y libini-config-dev libcurl4-openssl-dev curl libgcc1
RUN apt install -y python3-distutils libclang-6.0-dev protobuf-compiler python3-pip

WORKDIR /tmp

# Download and install TSS 2.0
RUN git clone https://github.com/tpm2-software/tpm2-tss.git --branch 2.3.3
RUN cd tpm2-tss \
	&& ./bootstrap \
	&& ./configure \
	&& make -j$(nproc) \
	&& make install \
	&& ldconfig
RUN rm -rf tpm2-tss

# Download and install TPM 2.0 Tools verison 4.1.1
RUN git clone https://github.com/tpm2-software/tpm2-tools.git --branch 4.1.1
RUN cd tpm2-tools \
    && ./bootstrap \
    && ./configure --prefix=/usr \
    && make -j$(nproc) \
    && make install
RUN rm -rf tpm2-tools

# Download and install software TPM
ARG ibmtpm_name=ibmtpm1637
RUN wget -L "https://downloads.sourceforge.net/project/ibmswtpm2/$ibmtpm_name.tar.gz"
RUN sha256sum $ibmtpm_name.tar.gz | grep ^dd3a4c3f7724243bc9ebcd5c39bbf87b82c696d1c1241cb8e5883534f6e2e327
RUN mkdir -p $ibmtpm_name \
	&& tar -xvf $ibmtpm_name.tar.gz -C $ibmtpm_name \
	&& chown -R root:root $ibmtpm_name \
	&& rm $ibmtpm_name.tar.gz
WORKDIR $ibmtpm_name/src
RUN sed -i 's/-DTPM_NUVOTON/-DTPM_NUVOTON $(CFLAGS)/' makefile
RUN CFLAGS="-DNV_MEMORY_SIZE=32768 -DMIN_EVICT_OBJECTS=7" make -j$(nproc) \
&& cp tpm_server /usr/local/bin
RUN rm -rf $ibmtpm_name/src $ibmtpm_name

# Download and install SoftHSMv2
WORKDIR /tmp
RUN git clone https://github.com/opendnssec/SoftHSMv2.git \
	&& cd SoftHSMv2 \
	&& git reset --hard 35938595f83923504751b40535570342f706a634

RUN cd SoftHSMv2 \
	&& sh autogen.sh \
	# Autogen might fail because of some limitations of autoconf, see:
	# https://bugzilla.redhat.com/show_bug.cgi?id=1826935#c3
	|| sh autogen.sh
RUN cd SoftHSMv2 \
	&& ./configure --disable-gost \
	&& make \
	&& make install
RUN rm -rf SoftHSMv2

# Download and install Mbed Crypto from Mbed TLS
RUN git clone https://github.com/ARMmbed/mbedtls.git \
	&& cd mbedtls \
	&& git reset --hard mbedtls-2.25.0
RUN cd mbedtls \
	&& ./scripts/config.py crypto \
	&& SHARED=1 make \
	&& make install

# Install dependencies for Trusted Services
# Install cmake v 3.18
RUN wget https://cmake.org/files/v3.18/cmake-3.18.0-Linux-x86_64.sh
RUN chmod +x cmake-3.18.0-Linux-x86_64.sh
RUN ./cmake-3.18.0-Linux-x86_64.sh --prefix=/usr/local --exclude-subdir --skip-license
RUN rm cmake-3.18.0-Linux-x86_64.sh

# Install nanopb
RUN wget https://jpa.kapsi.fi/nanopb/download/nanopb-0.4.4-linux-x86.tar.gz
RUN tar -xzvf nanopb-0.4.4-linux-x86.tar.gz
RUN cd nanopb-0.4.4-linux-x86 \
	&& cmake . \
	&& make \
	&& make install
RUN rm -rf nanopb-0.4.4-linux-x86 nanopb-0.4.4-linux-x86.tar.gz

# Install mock Trusted Services
# Setup git config for patching dependencies
RUN git config --global user.email "some@email.com"
RUN git config --global user.name "Parsec Team"
RUN git clone https://git.trustedfirmware.org/TS/trusted-services.git --branch integration \
	&& cd trusted-services \
	&& git reset --hard c1cf9120e4ab0b359a27176b079769b9a7e6bb87
# Install correct python dependencies
RUN pip3 install -r trusted-services/requirements.txt
RUN cd trusted-services/deployments/libts/linux-pc/ \
	&& cmake . \
	&& make \
	&& cp libts.so nanopb_install/lib/libprotobuf-nanopb.a mbedtls_install/lib/libmbedcrypto.a /usr/local/lib/
RUN rm -rf trusted-services

# Create a new token in a new slot. The slot number assigned will be random
# and is found with the find_slot_number script.
RUN softhsm2-util --init-token --slot 0 --label "Parsec Tests" --pin 123456 --so-pin 123456

# Install Rust toolchain for all users
# This way of installing allows all users to call the same binaries, but non-root
# users cannot modify the toolchains or install new ones.
# See: https://github.com/rust-lang/rustup/issues/1085
ENV RUSTUP_HOME /opt/rust
ENV CARGO_HOME /opt/rust
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --no-modify-path
ENV PATH="/root/.cargo/bin:/opt/rust/bin:${PATH}"

# Install the wrappers for the Rust binaries installed earlier
COPY _exec_wrapper /usr/local/bin/
RUN ls /opt/rust/bin | xargs -n1 -I% ln -s /usr/local/bin/_exec_wrapper /usr/local/bin/$(basename %)

# Add users for multitenancy tests
RUN useradd -m parsec-client-1
RUN useradd -m parsec-client-2

# Add `/usr/local/lib` to library path for Trusted service provider
ENV LD_LIBRARY_PATH="/usr/local/lib"

# During end-to-end tests, Parsec is configured with the socket in /tmp/
# Individual tests might change that, but set the default after.
ENV PARSEC_SERVICE_ENDPOINT="unix:/tmp/parsec.sock"

# Generate keys for the key mappings test
COPY generate-keys.sh /tmp/
RUN ./generate-keys.sh

# Import an old version of the e2e tests
COPY import-old-e2e-tests.sh /tmp/
RUN ./import-old-e2e-tests.sh

# Download the SPIRE server and agent
RUN curl -s -N -L https://github.com/spiffe/spire/releases/download/v0.11.1/spire-0.11.1-linux-x86_64-glibc.tar.gz | tar xz
ENV SPIFFE_ENDPOINT_SOCKET="unix:///tmp/agent.sock"
