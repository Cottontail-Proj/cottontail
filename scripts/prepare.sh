#!/bin/bash
# prepare.sh - Install all essential dependencies for Cottontail on Ubuntu 18.04 (native, not Docker)

set -e

echo "Updating package lists..."
sudo apt-get update

echo "Installing essential system packages..."
sudo apt-get install -y \
    dpkg-dev \
    make \
    libc6-dev \
    git \
    wget \
    curl \
    software-properties-common \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-dev \
    zlib1g-dev \
    libzstd-dev \
    libcurl4-openssl-dev \
    libreadline-dev \
    tcl \
    doxygen \
    graphviz \
    ninja-build \
    vim \
    libssl-dev

echo "Installing Z3 from source (version 4.11.2)..."
git clone --branch z3-4.11.2 --depth 1 https://github.com/Z3Prover/z3.git ~/z3
cd ~/z3
python3 scripts/mk_make.py --prefix=$HOME/.local
cd build
make -j$(nproc)
make install
cd ~
rm -rf ~/z3

export Z3_DIR=$HOME/.local

echo "Searching for Z3 CMake config files..."
find $HOME/.local -name "Z3Config.cmake" -o -name "z3-config.cmake" -print

echo "Installing newer CMake (v3.20.0)..."
wget https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-linux-x86_64.tar.gz
tar -xzvf cmake-3.20.0-linux-x86_64.tar.gz
mv cmake-3.20.0-linux-x86_64 $HOME/.local/cmake-3.20.0
ln -sf $HOME/.local/cmake-3.20.0/bin/cmake $HOME/.local/bin/cmake
rm cmake-3.20.0-linux-x86_64.tar.gz

export PATH="$HOME/.local/bin:$PATH"

echo "Installing LLVM-11 using the official LLVM script..."
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 11
rm llvm.sh

echo "Setting LLVM-11 as default..."
sudo update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 100
sudo update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 100
sudo update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-11 100

echo "Upgrading pip and installing Python dependencies..."
python3 -m pip install --user --upgrade pip setuptools wheel
python3 -m pip install --user \
    lit \
    gcovr \
    openai \
    requests \
    configparser \
    z3-solver

echo "All dependencies installed successfully."