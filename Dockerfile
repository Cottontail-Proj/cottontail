FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=UTC

# Install essential packages and dependencies first
RUN apt-get update && apt-get install -y \
    dpkg-dev \
    build-essential \
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
    libssl-dev \
    zlib1g-dev \
    libncurses5-dev \
    libncursesw5-dev \
    libreadline-dev \
    libsqlite3-dev \
    libgdbm-dev \
    libdb5.3-dev \
    libbz2-dev \
    libexpat1-dev \
    liblzma-dev \
    libffi-dev \
    uuid-dev \
    libzstd-dev \
    libcurl4-openssl-dev \
    tcl \
    doxygen \
    graphviz \
    ninja-build \
    sudo \
    vim \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://www.python.org/ftp/python/3.10.13/Python-3.10.13.tgz && \
    tar xvf Python-3.10.13.tgz && \
    cd Python-3.10.13 && \
    ./configure --enable-optimizations --with-ensurepip=install && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && \
    rm -rf Python-3.10.13*

# install Z3 from source using py3.10
RUN git clone --branch z3-4.11.2 --depth 1 https://github.com/Z3Prover/z3.git /tmp/z3 && \
    cd /tmp/z3 && \
    python3.10 scripts/mk_make.py --prefix=/usr/local && \
    cd build && \
    make -j$(nproc) && \
    make install && \
    rm -rf /tmp/z3

ENV Z3_DIR=/usr/local

# innstall CMake
RUN wget https://github.com/Kitware/CMake/releases/download/v3.20.0/cmake-3.20.0-linux-x86_64.tar.gz && \
    tar -xzvf cmake-3.20.0-linux-x86_64.tar.gz && \
    mv cmake-3.20.0-linux-x86_64 /opt/cmake && \
    ln -s /opt/cmake/bin/cmake /usr/local/bin/cmake && \
    rm cmake-3.20.0-linux-x86_64.tar.gz

# install LLVM-11 with py3.8
RUN wget https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh 11 && \
    rm llvm.sh && \
    rm -rf /var/lib/apt/lists/*

# set py3.10 as default
RUN update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.10 100 && \
    update-alternatives --set python3 /usr/local/bin/python3.10 && \
    ln -sf /usr/local/bin/pip3.10 /usr/bin/pip3

RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 100 \
    && update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 100 \
    && update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-11 100

# add newer deps using py3.10
RUN python3.10 -m pip install --upgrade pip setuptools wheel
RUN python3.10 -m pip install \
    lit \
    gcovr \
    openai \
    requests \
    configparser \
    z3-solver

WORKDIR /cottontail
COPY . /cottontail/

# build cottontail compiler
WORKDIR /cottontail/cottontail-compiler
RUN chmod +x build-cottontail-compiler-docker.sh
RUN ./build-cottontail-compiler-docker.sh

WORKDIR /cottontail/benchmark-test
RUN chmod +x build-json-c.sh

RUN mkdir -p input output failed-cases gpt-output gpt-output-raw z3-output

ENV PATH="/cottontail/cottontail-compiler/build:${PATH}"
ENV COTTONTAIL_ROOT="/cottontail"

RUN ./build-json-c.sh

RUN cp /cottontail/config/config.docker.ini /cottontail/benchmark-test/config.ini

WORKDIR /cottontail/benchmark-test