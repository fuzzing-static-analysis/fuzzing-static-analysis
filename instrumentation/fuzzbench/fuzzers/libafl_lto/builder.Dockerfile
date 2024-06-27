# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

ARG parent_image
FROM $parent_image

# Uninstall old Rust & Install the latest one.
RUN if which rustup; then rustup self uninstall -y; fi && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs > /rustup.sh && \
    sh /rustup.sh --default-toolchain nightly-2023-03-29 -y && \
    rm /rustup.sh

# Install dependencies.
RUN apt-get update && \
    apt-get remove -y llvm-10 && \
    apt-get install -y \
        build-essential \
        cargo && \
    apt-get install -y wget libstdc++5 libtool-bin automake flex bison \
        libglib2.0-dev libpixman-1-dev python3-setuptools unzip \
        lsb-release wget software-properties-common gnupg \
        apt-utils apt-transport-https ca-certificates joe curl nlohmann-json3-dev

# LLVM

RUN wget https://apt.llvm.org/llvm.sh
RUN chmod +x llvm.sh
RUN ./llvm.sh 15

RUN rm -rf /usr/local/bin/llvm-*
RUN export PATH="$PATH:/usr/local/llvm-15/bin"

RUN apt install

RUN apt install -y libc++-15-dev libc++1-15 libc++abi1-15 libunwind-15 libunwind-15-dev libc++abi-15-dev

# COPY libafl.
COPY ./LibAFL /libafl

# Checkout a current commit
# RUN cd /libafl && git checkout 8ff8ae41f1ed2956bb1e906c5c7bd0505ca110c0 || true
# Note that due a nightly bug it is currently fixed to a known version on top!

# Create analysis directory
RUN mkdir /out/analysis && mkdir /out/ddg

# Compile libafl.
RUN cd /libafl && \
    unset CFLAGS CXXFLAGS && \
    export LIBAFL_EDGES_MAP_SIZE=2621440 && \
    export ANALYSIS_OUTPUT_PATH='/out/analysis' && \
    export DDG_OUTPUT_PATH='/out/ddg' && \
    cd ./fuzzers/fuzzbench && \
    PATH="/root/.cargo/bin/:$PATH" cargo build --release --features no_link_main

# Auxiliary weak references.
RUN cd /libafl/fuzzers/fuzzbench && \
    clang -c stub_rt.c && \
    ar r /stub_rt.a stub_rt.o
