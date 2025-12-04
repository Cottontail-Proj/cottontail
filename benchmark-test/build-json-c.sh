#!/bin/bash

# prepare the source code of json-c
wget https://github.com/json-c/json-c/archive/refs/tags/json-c-0.18-20240915.tar.gz
tar -xf json-c-0.18-20240915.tar.gz
mv json-c-json-c-0.18-20240915 json-c

# prepare the binary with gcov and sanitizer
cd json-c
mkdir build-gcov
cd build-gcov
cmake -DCMAKE_C_COMPILER=gcc -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="--coverage -fprofile-arcs -ftest-coverage -g -O0 -fsanitize=address -ldl -static-libasan" -DCMAKE_INSTALL_PREFIX=$PWD -DBUILD_SHARED_LIBS=OFF ..
make -j12
cd ..

# prepare the binary with cottontail concolic execution
export PATH=$PWD/../../cottontail-compiler/build:$PATH
mkdir build-cottontail
cd build-cottontail
cmake -DCMAKE_C_COMPILER=cottontail-cc -DCMAKE_INSTALL_PREFIX=$PWD -DCMAKE_C_FLAGS="-g -O0 -fno-discard-value-names"  ..
make -j12
cp *.json ../../
cd ..
cd ..

cp ../scripts/run-cottontail.py .
cp ../config/config.ini .
cp ../scripts/collect_coverage.sh json-c/build-gcov/apps/



