#!/usr/bin/env bash

# ------------------------------------------------------------------------------
# Copyright (c) 2019, Arm Limited, All Rights Reserved
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#          http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ------------------------------------------------------------------------------

set -e

# The clean up procedure is called when the script finished or is interrupted
cleanup() {
    echo "Shutdown Parsec and clean up"
    # Stop Parsec if running
    if [ -n "$PARSEC_PID" ]; then kill $PARSEC_PID || true; fi
    # Stop tpm_server if running
    if [ -n "$TPM_SRV_PID" ]; then kill $TPM_SRV_PID || true; fi
    # Remove the slot_number line added by find_slot_number.sh
    sed -i '/^slot_number =.*/d' $CONFIG_PATH
    # Remove fake mapping and temp files
    if [ -d "mappings" ]; then rm -rf -- "mappings"; fi
    if [ -d "pkcs11_mappings" ]; then rm -rf -- "pkcs11_mappings"; fi
    if [ -d "mbed_mappings" ]; then rm -rf -- "mbed_mappings"; fi
    if [ -f "NVChip" ]; then rm "NVChip"; fi

    if [ -z "$NO_CARGO_CLEAN" ]; then cargo clean; fi
}

usage() {
    printf "
Continuous Integration test script

This script will execute various tests targeting a platform with a
single provider or all providers included.
It is meant to be executed inside one of the container
which Dockerfiles are in tests/per_provider/provider_cfg/*/
or tests/all_providers/

Usage: ./tests/ci.sh [--no-cargo-clean] [--no-stress-test] PROVIDER_NAME
where PROVIDER_NAME can be one of:
    - mbed-crypto
    - pkcs11
    - tpm
    - all
"
}

error_msg() {
    echo "Error: $1"
    usage
    exit 1
}

# Parse arguments
NO_CARGO_CLEAN=
NO_STRESS_TEST=
PROVIDER_NAME=
while [ "$#" -gt 0 ]; do
    case "$1" in
    --no-cargo-clean)
        NO_CARGO_CLEAN="True"
        ;;
    --no-stress-test)
        NO_STRESS_TEST="True"
        ;;
    mbed-crypto | pkcs11 | tpm | all)
        if [ -n "$PROVIDER_NAME" ]; then
            error_msg "Only one provider name must be given"
        fi
        PROVIDER_NAME=$1
        if [ "$PROVIDER_NAME" = "all" ]; then
            FEATURES="--features=all-providers"
            CONFIG_PATH="tests/all_providers/config.toml"
        else
            FEATURES="--features=$1-provider"
            CONFIG_PATH="tests/per_provider/provider_cfg/$1/config.toml"
        fi
        ;;
    *)
        error_msg "Unknown argument: $1"
        ;;
    esac
    shift
done

# Check if the PROVIDER_NAME was given.
if [ -z "$PROVIDER_NAME" ]; then
    error_msg "a provider name needs to be given as input argument to that script."
fi

trap cleanup EXIT

if [ "$PROVIDER_NAME" = "tpm" ] || [ "$PROVIDER_NAME" = "all" ]; then
    # Start and configure TPM server
    tpm_server &
    TPM_SRV_PID=$!
    sleep 5
    tpm2_startup -c -T mssim 2>/dev/null
    tpm2_changeauth -c owner tpm_pass 2>/dev/null
fi

if [ "$PROVIDER_NAME" = "pkcs11" ] || [ "$PROVIDER_NAME" = "all" ]; then
    # Find and append the slot number at the end of the configuration file.
    tests/per_provider/provider_cfg/pkcs11/find_slot_number.sh $CONFIG_PATH
fi

echo "Build test"
RUST_BACKTRACE=1 cargo build $FEATURES

echo "Static checks"
# On native target clippy or fmt might not be available.
if rustup component list | grep -q fmt; then
    cargo fmt --all -- --check
fi
if rustup component list | grep -q clippy; then
    cargo clippy --all-targets $FEATURES -- -D clippy::all -D clippy::cargo
fi

echo "Unit tests"
RUST_BACKTRACE=1 cargo test --lib $FEATURES
echo "Doc tests"
RUST_BACKTRACE=1 cargo test --doc $FEATURES

echo "Start Parsec for integration tests"
RUST_LOG=info RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
PARSEC_PID=$!
# Sleep time needed to make sure Parsec is ready before launching the tests.
sleep 5

# Check that Parsec successfully started and is running
pgrep -f target/debug/parsec >/dev/null

if [ "$PROVIDER_NAME" = "all" ]; then
    echo "Execute all-providers tests"
    RUST_BACKTRACE=1 cargo test $FEATURES all_providers
else
    # Per provider tests
    echo "Execute normal tests"
    RUST_BACKTRACE=1 cargo test $FEATURES normal_tests

    echo "Execute persistent test, before the reload"
    RUST_BACKTRACE=1 cargo test $FEATURES persistent_before

    # Create a fake mapping file for the root application, the provider and a
    # key name of "Test Key". It contains a valid PSA Key ID.
    # It is tested in test "should_have_been_deleted".
    # This test does not make sense for the TPM provider.
    if [ "$PROVIDER_NAME" = "mbed-crypto" ]; then
        echo "Create a fake mapping file for Mbed Provider"
        mkdir -p mbed_mappings/cm9vdA==/1
        printf '\x04\x00\x00\x00\x00\x00\x00\x00\xd6\xcb\xf8\x23\x09\x00\x00\x00' >mbed_mappings/cm9vdA==/1/VGVzdCBLZXk\=
        printf '\x00\x04\x00\x00\x01\x00\x00\x00\x00\x01\x01\x01\x01\x00\x05\x00' >>mbed_mappings/cm9vdA==/1/VGVzdCBLZXk\=
        printf '\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00' >>mbed_mappings/cm9vdA==/1/VGVzdCBLZXk\=
    elif [ "$PROVIDER_NAME" = "pkcs11" ]; then
        echo "Create a fake mapping file for PKCS 11 Provider"
        mkdir -p pkcs11_mappings/cm9vdA==/2
        printf '\x04\x00\x00\x00\x00\x00\x00\x00\xd6\xcb\xf8\x23\x09\x00\x00\x00' >pkcs11_mappings/cm9vdA==/2/VGVzdCBLZXk\=
        printf '\x00\x04\x00\x00\x01\x00\x00\x00\x00\x01\x01\x01\x01\x00\x05\x00' >>pkcs11_mappings/cm9vdA==/2/VGVzdCBLZXk\=
        printf '\x00\x00\x00\x00\x00\x00\x06\x00\x00\x00' >>pkcs11_mappings/cm9vdA==/2/VGVzdCBLZXk\=
    fi

    echo "Trigger a configuration reload to load the new mappings"
    kill -s SIGHUP $PARSEC_PID
    # Sleep time needed to make sure Parsec is ready before launching the tests.
    sleep 5

    echo "Execute persistent test, after the reload"
    RUST_BACKTRACE=1 cargo test $FEATURES persistent_after

    if [ -z "$NO_STRESS_TEST" ]; then
        echo "Shutdown Parsec"
        kill $PARSEC_PID
        # Sleep time needed to make sure Parsec is killed.
        sleep 2

        echo "Start Parsec for stress tests"
        # Change the log level for the stress tests because logging is limited on the
        # CI servers.
        RUST_LOG=error RUST_BACKTRACE=1 cargo run $FEATURES -- --config $CONFIG_PATH &
        PARSEC_PID=$!
        sleep 5

        echo "Execute stress tests"
        RUST_BACKTRACE=1 cargo test $FEATURES stress_test
    fi
fi
