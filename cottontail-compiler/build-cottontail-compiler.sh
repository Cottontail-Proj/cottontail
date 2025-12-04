#!/bin/bash

#export PATH=/usr/lib/llvm-11/bin:$PATH
export CC=clang
export CXX=clang++
export LLVM_DIR=$(llvm-config --cmakedir)

# build cottontail compiler
mkdir build && cd build

cmake -DCottontail_RT_BACKEND=qsym -DZ3_TRUST_SYSTEM_VERSION=on ..

make -j12


