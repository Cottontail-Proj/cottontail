# Note: All implementation code of the `cottontail` tool and scripts for reproducing the experiments will be released upon acceptance.

# Cottontail Artifact

`Cottontail` is a new concolic execution engine driven by large language models (LLMs). It is built on top of [SymCC](https://github.com/eurecom-s3/symcc) but integrates with three new concrete components. A more complete program path representation, named Expressive Structural Coverage Tree (ESCT), is first constructed to select structure-aware path constraints. Later, an LLM-driven constraint solver based on a *Solve-Complete* paradigm is designed to solve the path constraints smartly to get test inputs that are not only satisfiable to the constraints but also valid to the input syntax. Finally, a history-guided seed acquisition is employed to obtain new highly structured test inputs either before testing starts or after testing is saturated.

## Folder structure

```
Cottontail-Artifact
├── benchmark-test/       # Directory for running an example of benchmarks
├── build-cottontail/     # Build output directory for Cottontail
├── compiler/             # Cottontail compiler source code
├── docs/                 # Documentation files
├── example/              # Example inputs or usage
├── runtime/              # Runtime libraries and support files
├── scripts/              # Utility and helper scripts
├── test/                 # Test cases and testing framework
├── CMakeLists.txt        # CMake build configuration
├── LICENSE               # License file
├── README.md             # Project readme
├── build-cottontail-compiler.sh  # Shell script to build the compiler
├── pre-deps.sh           # Script to install prerequisites/dependencies
└── run-cottontail.py     # Main Python script to run concolic testing
```

## 1. Setup and Usage

### 1.1. Installing Dependencies

We provide a helper script `pre-deps.sh` which runs the required steps to ensure that all dependencies are provided:

```bash
./pre-deps.sh
```

* Please note that building `LLVM-10` from source code takes time; feel free to disable this process if you have already installed it.


### 1.2. Build the `cottontail` compiler

Utilize the `run.sh` script to build `cottontail-cc` compiler. The command is as follows (make sure the LLVM-10 toolchain is correctly set):

```bash
 ./build-cottontail-compiler.sh
```

After the above stage, we can use the customized compiler (i.e., contontail-cc) that supports concolic execution functionalities to build the testing subject.


### 1.3. Build test programs (via an example)

The `benchmarks-test` folder is used to run an example of benchmarks.

```bash
./build-json-c.sh
```

### 1.4. Configure the running settings

```bash
vim config.ini
```

```
[common-settings]
format = JSON
llm_model = xxx
api_key = xxx

[gcov-locations]
mainDir = xx
gcovDir = %(maindir)s/json-c/build-gcov/apps/
sourceDir = %(maindir)s/json-c/
recordFile = %(maindir)s/json-c/build-gcov/all_records.txt

[running-locations]
mainDir = xx
inputDir = %(maindir)s/input
outputDir = %(maindir)s/output
failedDir = %(maindir)s/failed-cases

[running-targets]
cottontailTarget = json_parse_cottontail
gcovTarget = json_parse_gcov

[running-params]
timeout = 43200 // running timeout
cov_timeout = 60 // interval timeout for coverage collection
```

### 1.5. Launch concolic testing


```bash
python run-cottontail.py
```

## 2. Special Thanks

We would like to thank the creators of [SymCC]([https://github.com/aflnet/aflnet](https://github.com/eurecom-s3/symcc)) for the tooling and infrastructure they have provided to the community and the developers of [MuJS](https://github.com/ccxvii/mujs) and [QuickJS](https://github.com/quickjs-ng/quickjs) for their swift fixing of our reported issues. We also appreciate anonymous reviewers for their insightful comments on improving the previous version of the paper.

## 3. License

This artifact is licensed under the GNU GENERAL PUBLIC LICENSE.
