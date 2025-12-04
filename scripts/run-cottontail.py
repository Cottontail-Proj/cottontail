#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import openai
import json
from z3 import *
from datetime import datetime
import timeit
from configparser import ConfigParser
try:
    from ollama import chat, ChatResponse
except ImportError:
    chat = None
    ChatResponse = None
import openai
import requests
import codecs
from openai import OpenAI
from openai._exceptions import RateLimitError


def usage():
    """
    Replicates the original usage() function in Bash.
    """
    print(
        "Usage: fuzzer.py -i INPUT_DIR [-o OUTPUT_DIR] [-f FAILED_DIR] TARGET...\n\n"
        "Run SymCC-instrumented TARGET in a loop, feeding newly generated inputs back\n"
        "into it. Initial inputs are expected in INPUT_DIR, and new inputs are\n"
        "continuously read from there. If OUTPUT_DIR is specified, a copy of the corpus\n"
        "and of each generated input is preserved there. TARGET may contain the special\n"
        'string "@@", which is replaced with the name of the current input file.\n'
        "If FAILED_DIR is specified, a copy of the failing test cases is preserved there.\n\n"
        "Note that SymCC never changes the length of the input, so be sure that the\n"
        "initial inputs cover all required input lengths.\n"
    )


COTPRMOPT = {
    "JSON": "You are a powerful and customized constraint solver. Your task is to solve constraints in test inputs and refine them step by step. Follow these steps: \
1. Identify all Constraint Masks (`[k!n]`) in the test input and their corresponding constraints. \
    - If multiple masks exist, sort them by their indices (e.g., k!10 < k!57 < k!100). \
2. Solve each Constraint Mask: \
    - Replace `[k!n]` with the solution (the content should be the ASCII character that corresonds to the constant solution). \
    - Do not change the position when replace the solution with the mask. \
    - If the solution is escaped char like `\n` with the value 0xa, keep the solution as escaped char. \
3. Replace the Flexible Mask (`[xxx]`): \
    - Replace `[xxx]` (entire unit) with a meaningful, valid, and as complex as possible complex string, following the content of the char solved from previous constraint mask. \
4. Ensure the final output: \
    - Is valid JSON. \
    - Is enclosed in ```. \
    - Dont remove any char that controls the space, e.g., `\n`, `\t`... ```. \
    - Make sure the strings (along with their positions) before the Constraint Mask are unchanged. \
5. Always think step by step to ensure correctness (no need to output the steps) and only output the final answer. \
Below are examples to guide you" 
"Q1: Here is the path constraint ```(= #x00000074 ((_ sign_extend 24) k!27))```, here is the test input you need to change: \
```{  \
  \"user\": \"admin\", \
  \"resource\": [k!27][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!27]`. \
   - The constraint is `(= #x00000074 ((_ sign_extend 24) k!27))`. \
\
2. Solve the Constraint: \
   - Solution: 0x74, which is the ASCII character `t`. \
   - Replace `[k!27]` with `t`. \
\
3. Replace the Flexible Mask ([xxx]): \
   - Replace `[xxx]` with `true, \"permissions\":{\"read\":true,\"write\":false,\"execute\":true}}`. (Note: here the replacement can be any string starting with `t`, you can also append more complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JSON structure, i.e., adding `}` to the end to match the previous strings. \
5. Omit the thinking procedures and only give the final answer. \
\
A1: \
```\
{ \
  \"user\": \"admin\", \
  \"resource\": true, \"permissions\":{\"read\":true,\"write\":false,\"execute\":true}} \
} \
```\n" 
"Q2: Here are the path constraints: ```(= #x00000074 ((_ sign_extend 24) k!27)) and (= #x0000005b ((_ sign_extend 24) k!30))```, here is the test input you need to change: \
```{ \
  \"user\": \"admin\", \
  \"resource\": [k!27], [k!30][xxx]``` \
\
Think internally step by step: \
1. Identify All Constraint Masks: \
   - Found two masks: `[k!27]` and `[k!30]`. \
   - Sort them by indices: k!27 < k!30. \
\
2.1. Solve the First Mask (`[k!27]`): \
   - The constraint is `(= #x00000074 ((_ sign_extend 24) k!27))`. \
   - Solution: 0x74, which is the ASCII character `t`. \
   - Replace `[k!27]` with `t`. \
\
2.2. Solve the Second Mask (`[k!30]`): \
   - The constraint is `(= #x0000005b ((_ sign_extend 24) k!30))`. \
   - Solution: 0x5b, which is the ASCII character `[`. \
   - Replace `[k!30]` with `[`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Replace `[xxx]` with `\"name\": true], \"session\":{\"token\":\"abc123xyz456+=<>!@#$%^&*()_{}|~`\"`. (add first `]` to match the previous `[`) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JSON structure. \
\
5. Omit the thinking procedures and only give the final answer. \
A2: \
```{\
  \"user\": \"admin\", \
  \"resource\": t, [\"name\": true] \
}```\n"
\
"Q3: Here is the path constraint ```(= #x00000074 ((_ sign_extend 24) k!0))```, here is the test input you need to change: \
```[k!0][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!0]`. \
   - The constraint is `(= #x00000074 ((_ sign_extend 24) k!0))`. \
\
2. Solve the Constraint: \
   - Solution: 0x74, which is the ASCII character `t`. \
   - Replace `[k!0]` with `t`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Replace `[xxx]` with `true`. (Note: here the replacement can be any string starting with `t` as long as the leading char can form a valid JSON string) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JSON structure, i.e., adding `}` to the end to match the previous strings. \
5. Omit the thinking procedures and only give the final answer. \
\
A3: \
```true```\n"
"Now answer the following: \
\
Q: Here are the path constraints:\
{dynamic_constraints} \
Here is the test input you need to change:\
{dynamic_test_input}\n",
    "XML":  "You are a powerful and customized constraint solver. Your task is to solve constraints in test inputs and refine them step by step. Follow these steps: \
1. Identify all Constraint Masks (`[k!n]`) in the test input and their corresponding constraints. \
    - If multiple masks exist, sort them by their indices (e.g., k!10 < k!57 < k!100). \
2. Solve each Constraint Mask: \
    - Replace `[k!n]` with the solution (the content should be the ASCII character that corresonds to the constant solution). \
    - You should sove it to meanful (syntax valid) solution (can be keywords or other features features) to make the combining string valid. \
    - The replacing position should not be changed. \
3. Replace the Flexible Mask (`[xxx]`): \
    - Think about the grammar of XML: there are many defined tag/attribute names or declarations. Follow the syntax or grammar rules of XML. \
    - Replace [xxx] with a meaningful, valid, and complex string, following the content of the char solved from previous constraint mask. \
4. Ensure the final output: \
    - Adheres to the original input format. \
    - Is valid XML code. \
    - Is enclosed in ```. \
    - Make sure the strings (along with their positions) before the Constraint Mask are unchanged. \
5. Always think step by step to ensure correctness (no need to output the steps) and only output the final answer. \
Below are examples to guide you.\n"
"Q1: Here is the path constraint ```(not (= #x00000021 ((_ zero_extend 24) k!14)))```, here is the test input you need to change: \
```<user><id>123[k!14][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: [k!14]. \
   - The constraint is `(not (= #x00000021 ((_ zero_extend 24) k!14)))`. \
\
2. Solve the Constraint: \
   - The solution can be any string except the one with ASCII code 0x21, but we should not randomly select. \
   - Instead, pick one value that can make the string starting with ``<user><id>123` valid: think about any previously defined tag/attribute names.\
   - Solution: 0x3c, which is the ASCII character `<`, as this string potentially matches the `</id>`, which can make the whole string valid. \
   - Replace `[k!14]` with `<`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Replace `[xxx]` with `/id><details><name>John Doe</name><email>johndoe@example.com</email></details></user>`. (Note: here the replacement can be any string starting with `<`, you can also append more complex but valid XML strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain XML structure, i.e., adding `</>` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
\
A1: \
```<user><id>123</id><details><name>John Doe</name><email>johndoe@example.com</email></details></user>```\n"   \
"Q2: Here is the path constraint ```(not (= #x00000021 ((_ zero_extend 24) k!17)))```, here is the test input you need to change: \
```<user><id>123</i[k!17][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!17]`. \
   - The constraint is `(not (= #x00000021 ((_ zero_extend 24) k!17)))`. \
\
2. Solve the Constraint: \
   - The solution can be any string except the one with ASCII code 0x21, but we should not randomly select. \
   - Instead, pick one value that can make the string starting with ``<user><id>123</i` valid: think about any previously defined tag/attribute names.\
   - Solution: 0x64, which is the ASCII character `d`, as this string potentially matches the tag name `id`, which can make the whole string valid. \
   - Replace [k!17] with `d`. \
\
3. Replace the Flexible Mask ([xxx]): \
   - Think what next string starting with `d` can make the whole string a valid XML string. \
   - Replace `[xxx]` with `d><role>admin</role><preferences><theme>dark</theme><notifications>enabled</notifications></preferences></user>`, so the whole string is a valid XML. (Note: here the replacement can be any string starting with `d`, you can also append other complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JavaScript structure, i.e., adding `</>` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
A2: \
```<user><id>123</id><role>admin</role><preferences><theme>dark</theme><notifications>enabled</notifications></preferences></user>```\n"   \
"Q3: Here is the path constraint ```(bvsle #x00000078 (concat #x000000 k!0))```, here is the test input you need to change: \
```[k!0][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!0]`. \
   - The constraint is `(bvsle #x00000078 (concat #x000000 k!0))`. \
\
2. Solve the Constraint: \
   - The solution can be any string between ASCII values from 0 to 120, but you should not randomly select. \
   - Instead, pick one value that can make the string starting with the solution valid.\
   - Solution: 0x3c, which is the ASCII character `<`, because `<` is the starting char of XML and can form many complex XML strings. \
   - Replace `[k!0]` with `<`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Think what previous string starting with `<` can make the whole string a valid and complex XML. \
   - Replace `[xxx]` with `person><name>Jane Doe</name><age>29</age><address><city>New York</city><zipcode>10001</zipcode></address></person>`, so the whole string is valid. (Note: here the replacement can be any string starting with `<` from the previous constraint mask, you can also append other complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain XML structure, i.e., adding `</>` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
A3: \
```<person><name>Jane Doe</name><age>29</age><address><city>New York</city><zipcode>10001</zipcode></address></person>```\n"   \
"Now answer the following: \
\
Q: Here are the path constraints:\
{dynamic_constraints} \
Here is the test input you need to change:\
{dynamic_test_input}\n",
    "URI": "libxml2-v2.13.5_ce",
    "SQL": "You are a powerful and customized constraint solver. Your task is to solve constraints in test inputs and refine them step by step. Follow these steps: \
1. Identify all Constraint Masks (`[k!n]`) in the test input and their corresponding constraints. \
    - If multiple masks exist, sort them by their indices (e.g., k!10 < k!57 < k!100). \
2. Solve each Constraint Mask: \
    - Replace `[k!n]` with the solution (the content should be the ASCII character that corresonds to the constant solution). \
    - You should sove it to meanful (syntax valid) solution (can be keywords or other features features) to make the combining string valid. \
    - The replacing position should not be changed. \
3. Replace the Flexible Mask (`[xxx]`): \
    - Think about the grammar of SQL: there are many keywords or defined table names. Follow the syntax or grammar rules of SQL. \
    - Replace `[xxx]` with a meaningful, valid, and complex string, following the content of the char solved from previous constraint mask. \
4. Ensure the final output: \
    - Adheres to the original input format. \
    - Is valid SQL code. \
    - Is enclosed in ```. \
    - Make sure the strings (along with their positions) *before* the Constraint Mask are unchanged. \
5. Always think step by step to ensure correctness (no need to output the steps) and only output the final answer. \
Below are examples to guide you. \n" 
"Q1: Here is the path constraint ```(and (= #x74 k!14) (= #x31 k!15))```, here is the test input you need to change: \
```CREATE TABLE [k!14][k!15][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found masks: `[k!14]` and `[k!15]`. \
   - The constraint is `(and (= #x74 k!14) (= #x31 k!15))`. \
\
2. Solve the Constraint: \
   - Solution for `[k!14]`: 0x74, which is the ASCII character `t`. \
   - Solution for `[k!15]`: 0x31, which is the ASCII character `1`. \
   - Replace `[k!14]` with `t` and `[k!15]` with `1`. \
\
3. Replace the Flexible Mask ([xxx]): \
   - Think about SQL grammar or syntax, give any valid SQL string that could make the whole string combing with `CREATE TABLE t1` valid.\
   - Replace [xxx] with ` (id INTEGER PRIMARY KEY, name TEXT);`. (Note: here the replacement can be any string starting with `CREATE TABLE t1`, you can also append more complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JavaScript structure, i.e., adding `;` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
\
A1: \
```CREATE TABLE t1 (id INTEGER PRIMARY KEY, name TEXT);```\n"   \
"Q2: Here is the path constraint ```(= #x0000002d ((_ sign_extend 24) k!0))```, here is the test input you need to change: \
```[k!0][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!0]`. \
   - The constraint is `(!= #x0000002d ((_ sign_extend 24) k!0))`. \
\
2. Solve the Constraint: \
   - Solution: 0x43, which is the ASCII character `-`. \
   - Replace `[k!0]` with `C`. \
   - (Can be any char that can satisfy the constraints and also can make a valid SQL string) \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Think what remaining string starting with `C` can make the whole string a valid SQL. \
   - Replace `[xxx]` with `CREATE TABLE test (c1 TEXT PRIMARY KEY) WITHOUT ROWID; CREATE INDEX index_0 ON test(c1 COLLATE NOCASE); INSERT INTO test(c1) VALUES ('A'); INSERT INTO test(c1) VALUES ('a'); PRAGMA integrity_check;`, so the whole string is a valid SQL. (Note: `CREATE` is a keyword in SQL, so here the replacement can be any string starting with the keywords and append any valid SQL string) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain SQL structure, i.e., adding `;` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
A2: \
```CREATE TABLE test (c1 TEXT PRIMARY KEY) WITHOUT ROWID; CREATE INDEX index_0 ON test(c1 COLLATE NOCASE); INSERT INTO test(c1) VALUES ('A'); INSERT INTO test(c1) VALUES ('a'); PRAGMA integrity_check;```\n"   \
"Now answer the following: \
\
Q: Here are the path constraints:\
{dynamic_constraints} \
Here is the test input you need to change:\
{dynamic_test_input}\n",
    "JavaScript": "You are a powerful and customized constraint solver. Your task is to solve constraints in test inputs and refine them step by step. Follow these steps: \
1. Identify all Constraint Masks (`[k!n]`) in the test input and their corresponding constraints. \
    - If multiple masks exist, sort them by their indices (e.g., k!10 < k!57 < k!100). \
2. Solve each Constraint Mask: \
    - Replace `[k!n]` with the solution (the content should be the ASCII character that corresonds to the constant solution). \
    - You should sove it to meanful (syntax valid) solution (can be keywords or other features features) to make the combining string valid. \
    - The replacing position should not be changed. \
3. Replace the Flexible Mask (`[xxx]`): \
    - Think about the grammar of JavaSript: there are many keywords or defined variable names. Follow the syntax or grammar rules of JavaScript. \
    - Replace `[xxx]` with a meaningful, valid, and complex string, following the content of the char solved from previous constraint mask. \
4. Ensure the final output: \
    - Adheres to the original input format. \
    - Is valid JavaScript code. \
    - Is enclosed in ```. \
    - Make sure the strings (along with their positions) before the Constraint Mask are unchanged. \
5. Always think step by step to ensure correctness (no need to output the steps) and only output the final answer. \
Below are examples to guide you. \n" 
"Q1: Here is the path constraint ```(= #x00000027 ((_ sign_extend 24) k!27))```, here is the test input you need to change: \
```eval(\"(function() { return [k!27][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!27]`. \
   - The constraint is `(= #x00000027 ((_ sign_extend 24) k!27))`. \
\
2. Solve the Constraint: \
   - Solution: 0x74, which is the ASCII character `'`. \
   - Replace `[k!27]` with `'`. \
\
3. Replace the Flexible Mask ([xxx]): \
   - Replace [xxx] with `Hello, World!'; })()\");`. (Note: here the replacement can be any string starting with `'`, you can also append more complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JavaScript structure, i.e., adding `}`, `;`, `)` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
\
A1: \
```eval(\"(function() { return 'Hello, World!'; })()\");```\n"   \
"Q2: Here is the path constraint ```(bvsle #x00000078 (concat #x000000 k!1))```, here is the test input you need to change: \
```e[k!1][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!1]`. \
   - The constraint is `(bvsle #x00000078 (concat #x000000 k!1))`. \
\
2. Solve the Constraint: \
   - The solution can be any string between ASCII values from 0 to 120, but you should not randomly select. \
   - Instead, pick one value that can make the string starting with `e` valid: think about any keyword or existing variable/function name that can make the remaining string valid.\
   - Solution: 0x76, which is the ASCII character `v`, because `eval` is a keyword in JavaScript. \
   - Replace `[k!1]` with `v`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Think what remaining string starting with `ev` can make the whole string a valid Javascript. \
   - Replace `[xxx]` with `al(\"(function() { return 'Hello, World!'; })()\");`, so the whole string is a valid JavaScript. (Note: here the replacement can be any string starting with `ev`, you can also append other complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JavaScript structure, i.e., adding `}`, `;`, `)` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
A2: \
```eval(\"(function() { return 'Hello, World!'; })()\");```\n"   \
"Q3: Here is the path constraint ```(bvsle #x00000078 (concat #x000000 k!0))```, here is the test input you need to change: \
```[k!0][xxx]``` \
\
Think internally step by step: \
1. Identify the Constraint Mask: \
   - Found one mask: `[k!0]`. \
   - The constraint is `(bvsle #x00000078 (concat #x000000 k!0))`. \
\
2. Solve the Constraint: \
   - The solution can be any string between ASCII values from 0 to 120, but you should not randomly select. \
   - Instead, pick one value that can make the string starting with the solution valid: think about any keyword (e.g., `let`, `eval`, and many others) or existing variable/function name that can make the remaining string valid.\
   - Solution: 0x6c, which is the ASCII character `l`, because `let` is a keyword in JavaScript. \
   - Replace `[k!0]` with `l`. \
\
3. Replace the Flexible Mask (`[xxx]`): \
   - Think what remaining string starting with `l` can make the whole string a valid Javascript. \
   - Replace `[xxx]` with `et last = (arr) => arr[arr.length - 1];`);`, so the whole string is a valid JavaScript. (Note: here the replacement can be any string starting with `l` from the previous constraint mask, you can also append other complex but valid strings) \
\
4. Ensure Validity: \
   - Add any necessary closing braces to maintain JavaScript structure, i.e., adding `}`, `;`, `)` to the end to match the previous strings if necessary. \
\
5. Omit the thinking procedures and only give the final answer. \
A3: \
```let last = (arr) => arr[arr.length - 1];```\n"   \
"Now answer the following: \
\
Q: Here are the path constraints:\
{dynamic_constraints} \
Here is the test input you need to change:\
{dynamic_test_input}\n",
}


COTPRMOPT_NORMAL = {
    "JSON": "You are a powerful and customized constraint solver. Your task is to solve constraints and try to make the solution both satisfiable with path constraints and syntax validity. Ensure the final solution is enclosed in ```",
    "XML":  "You are a powerful and customized constraint solver. Your task is to solve constraints and try to make the solution both satisfiable with path constraints and syntax validit. Ensure the final solution is enclosed in ```",
    "JavaScript": "You are a powerful and customized constraint solver. Your task is to solve constraints and try to make the solution both satisfiable with path constraints and syntax validit. Ensure the final solution is enclosed in ```",
    "SQL": "You are a powerful and customized constraint solver. Your task is to solve constraints and try to make the solution both satisfiable with path constraints and syntax validit. Ensure the final solution is enclosed in ```",
}

def run_command(cmd, timeout_sec=None, extra_env=None):
    """
    Runs a shell command with an optional timeout, capturing stdout/stderr to /dev/null.
    If extra_env is given, it merges those environment variables into the current environment.
    Returns (returncode, has_error), where has_error is a boolean indicating whether
    'ERROR' or 'core dumped' appeared in the output (if that matters).
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    # We replicate "timeout -k 5 90 <cmd>" by using the Linux `timeout` itself,
    # or we can do Python's built-in timeout. Let's do direct usage of the system's `timeout`
    # for closeness to the original script. Adjust as needed for your environment.
    #
    # "-k 5" means send SIGTERM after 90s, then SIGKILL after 5s if still alive.
    # We'll collect the command output in a pipe to check for "ERROR" or "core dumped".
    if timeout_sec is not None:
        # Construct the full command using system's timeout
        cmd = ["timeout", "-k", "5", str(timeout_sec)] + cmd

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,  # We don't raise exceptions for non-zero returns
        )
    except FileNotFoundError:
        # If 'timeout' is not found or the command doesn't exist
        return 127, False

    out_combined = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")
    # print("Output: ", proc.stdout)
    has_error = any(x in out_combined for x in ("ERROR: AddressSanitizer", "core dumped", "Segmentation"))
    return proc.returncode, has_error


def sha256_file(path: Path) -> str:
    """
    Compute the SHA256 of a file and return the hex digest.
    """
    hasher = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def copy_file_with_unique_name(file_path: Path, dest_dir: Path):
    """
    Copy one file to the destination directory, naming it according to its SHA-256 hash.
    """
    digest = sha256_file(file_path)
    dest_file = dest_dir / digest
    shutil.copyfile(file_path, dest_file)


def copy_with_unique_name(source_dir: Path, dest_dir: Path):
    """
    Copy all files in source_dir to dest_dir, each renamed to its SHA-256 hash.
    """
    if not source_dir.is_dir():
        return

    for child in source_dir.iterdir():
        if child.is_file():
            copy_file_with_unique_name(child, dest_dir)


def remove_analyzed(work_dir: Path, source_dir: Path):
    """
    Remove input files from source_dir that have already been analyzed,
    as recorded in work_dir/analyzed_inputs file.
    """
    analyzed_file = work_dir / "analyzed_inputs"
    if not analyzed_file.exists():
        return

    with analyzed_file.open("r") as f:
        analyzed_names = set(line.strip() for line in f.readlines())

    for child in source_dir.iterdir():
        if child.is_file() and child.name in analyzed_names:
            child.unlink()  # remove it


def maybe_import(in_dir: Path, work_dir: Path):
    """
    Copy any new input from in_dir to 'next' generation if not already analyzed.
    """
    next_dir = work_dir / "next"
    analyzed_file = work_dir / "analyzed_inputs"
    analyzed = set()
    if analyzed_file.exists():
        with analyzed_file.open("r") as f:
            for line in f:
                analyzed.add(line.strip())

    if in_dir.is_dir():
        for child in in_dir.iterdir():
            if child.is_file():
                # If not in analyzed and not already in next
                if child.name not in analyzed and not (next_dir / child.name).exists():
                    print(f"Importing {child} from the input directory")
                    shutil.copyfile(child, next_dir / child.name)


def maybe_export(source_dir: Path, out_dir: Path):
    """
    If out_dir is defined, copy the new files in source_dir there using unique naming.
    """
    if out_dir:
        copy_with_unique_name(source_dir, out_dir)


def save_failed(ret_code: int, input_file: Path, failed_dir: Path, has_error: bool):
    """
    If ret_code != 0 and we have a failed_dir, copy the input file there.
    However, in the original Bash script, it only copies if ret_code != 0
    *AND* has_error == 0. We replicate that precisely:
        if [ $ret_code -ne 0 ] && [[ -v failed_dir ]] && [[ $has_error -eq 0 ]]; then
            ...
    But in Python we treat has_error as boolean. So has_error == 0 means has_error is False.
    """
    if ret_code != 0 and failed_dir and has_error:
        copy_file_with_unique_name(input_file, failed_dir)


def report_coverage(args):
    """
    Reports coverage by navigating to the appropriate directory,
    running 'collect_coverage.sh' with os.system, and returning to the original directory.
    """
    print(f"Function executed at {time.ctime()}; start to report code coverage ...")

    # Map the program to its corresponding directory
    program = args["gcov_target"]

    # if program not in TARGDIR:
    #    raise ValueError(f"Program '{program}' is not in TARGDIR mapping!")

    # Construct the coverage directory path
    coverage_dir = args["gcov_dir"]
    # print(f"Constructed coverage_dir: {coverage_dir}")

    src_dir = args["source_dir"]

    # Ensure collect_coverage.sh exists
    script = coverage_dir / "collect_coverage.sh"
    if not script.exists():
        print(f"Error: Coverage script '{script}' does not exist.")
        return

    # Execute the script using os.system
    try:
        command = f"cd {coverage_dir} && ./collect_coverage.sh {src_dir} >/dev/null 2>&1"
        # print(f"Executing: {command}")
        os.system(command)
    except Exception as e:
        print(f"Error while running coverage script: {e}")


def json_file_to_string(json_file_path: str) -> str:
    """
    Reads a JSON file from the given path and returns its contents as a JSON string.

    :param json_file_path: Path to the JSON file.
    :return: The file's contents as a JSON-formatted string.
    """
    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)               # parse the file into a Python dict or list

    json_string = json.dumps(data, indent=2)  # convert back to a nicely formatted JSON string
    return json_string


def is_valid_test_case(test_case: dict, constraints: dict) -> bool:
    """
    Check whether 'test_case' meets the given 'constraints'.
    This is a placeholder function you can adapt as needed.

    Sample logic:
      - We assume test_case is something like { "name X": "some string" }.
      - We assume constraints might specify that the value must contain
        a certain substring, or meet a certain length, etc.
    """

    # 1) If test_case is empty, return False.
    if not test_case:
        return False

    # 2) Extract the first key-value pair (assuming there's only one).
    #    e.g. { "name 1": "solution 1" }
    (k, v) = next(iter(test_case.items()))

    # 3) Check constraints. We'll demonstrate "must_contain" and "min_length".
    must_contain = constraints.get("must_contain", "")
    min_length = constraints.get("min_length", 0)

    # v should contain must_contain
    if must_contain and must_contain not in v:
        return False

    # v should be at least min_length chars
    if len(v) < min_length:
        return False

    # Add more checks as needed:
    # if constraints.get("some_other_requirement"): ...
    #    ...
    return True


def store_valid_solutions(
    assistant_reply: str,
    folder: str,
    constraints_json: str
) -> None:
    """
    Parse the assistant_reply (a JSON array of objects), parse constraints_json,
    and only store valid items as 1.json, 2.json, etc., in the given folder.

    Example assistant_reply:
      [
        { "name 1": "solution 1" },
        { "name 2": "solution 2" },
        { "name 3": "solution 3" }
      ]

    Example constraints_json:
      {
        "must_contain": "solution",
        "min_length": 5
      }

    Only items that pass 'is_valid_test_case(item, constraints)' are saved.
    """

    # 1) Ensure the output folder exists
    os.makedirs(folder, exist_ok=True)

    # 2) Parse the JSON inputs
    test_cases = json.loads(assistant_reply)    # array of objects
    constraints = json.loads(constraints_json)  # constraints dictionary

    # 3) Iterate and validate
    valid_count = 0
    for idx, item in enumerate(test_cases, start=1):
        if is_valid_test_case(item, constraints):
            # If valid, save to (folder)/(idx).json
            valid_count += 1
            output_file = os.path.join(folder, f"{valid_count}.json")

            with open(output_file, "w", encoding="utf-8") as f:
                json.dump(item, f, ensure_ascii=False, indent=2)

            print(f"Stored valid solution #{valid_count} in '{output_file}'.")
        else:
            print(f"Skipping invalid test case #{idx}: {item}")

    print(f"\nTotal valid solutions saved: {valid_count}")


def read_file_content(fpath):
    """
    Reads the content of the file at the given path and returns it as a string,
    with leading and/or trailing triple backticks (```) removed if present.
    Converts actual newlines into the escape sequence `\n`.

    :param fpath: Path to the file (str or Path object)
    :return: The cleaned content of the file as a string
    """
    try:
        with open(fpath, "r", encoding="utf-8") as file:
            content = file.read().strip()

        # Replace actual newlines with `\n`
        content = content.replace("\n", "\\n")

        # Remove leading and/or trailing triple backticks if present
        if content.startswith("```"):
            content = content[3:].strip()
        if content.endswith("```"):
            content = content[:-3].strip()

        return content

    except FileNotFoundError:
        print(f"Error: File not found at {fpath}")
        return ""
    except Exception as e:
        print(f"Error reading file {fpath}: {e}")
        return ""

def remove_invalid_surrogates(text):
    """
    Remove lone surrogate characters which are invalid in UTF-8.
    """
    return ''.join(c for c in text if not (0xD800 <= ord(c) <= 0xDFFF))

def save_string_to_file(file_path, content):
    """
    Save a string to a file, removing any invalid Unicode characters (like lone surrogates).

    Args:
        file_path (str or Path): The path to the file where the string will be saved.
        content (str): The string content to save.

    Returns:
        None
    """
    file_path = Path(file_path)
    file_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        # Sanitize surrogate characters before writing
        cleaned_content = remove_invalid_surrogates(content)

        # Write sanitized content
        with open(file_path, "w", encoding="utf-8", errors="replace") as file:
            file.write(cleaned_content)

        # print(f"Content successfully saved to {file_path}")

    except Exception as e:
        print(f"Error saving content to {file_path}: {e}")


def sha256_content(content: str) -> str:
    """
    Compute the SHA256 of a string and return the hex digest.
    """
    hasher = hashlib.sha256()
    hasher.update(content.encode("utf-8"))
    return hasher.hexdigest()


def store_test_cases(input_file, output_folder):
    """
    Store the entire content of the input file into a single new file in the target folder.

    Args:
        input_file (str): Path to the input file.
        output_folder (str): Path to the output folder.

    Returns:
        list: A list containing the full path of the newly created file.
    """
    def sha256_content(content):
        """Compute the SHA-256 hash of a given string."""
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    # Ensure the output folder exists
    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    try:
        # Read the entire content of the input file
        with open(input_file, "r", encoding="utf-8") as file:
            content = file.read().strip()  # Remove surrounding whitespace

        # Remove leading and trailing backticks if present
        if content.startswith("```") and content.endswith("```"):
            content = content[3:-3].strip()

        # Handle escape sequences safely
        try:
            content = json.loads(f'"{content}"')  # Decode escape sequences safely
        except json.JSONDecodeError:
            content = content.encode("utf-8", errors="surrogatepass").decode("unicode_escape", errors="replace")

        # Compute the hash of the entire content for the filename
        hash_name = sha256_content(content)
        output_file = output_folder / f"{hash_name}"

        # Write the entire content to the output file
        with open(output_file, "w", encoding="utf-8") as out_file:
            out_file.write(content)

        # Return the file path as a list
        return [str(output_file)]

    except Exception as e:
        print(f"Error processing file: {e}")
        return []


def store_test_cases_with_count(input_file, output_folder, cnt=0):
    """
    Store the content of the input file into a new file,
    decoding basic escape sequences while preserving or avoiding invalid Unicode characters.

    Args:
        input_file (str): Path to the input file.
        output_folder (str): Path to the output folder.
        cnt (int): Counter for naming the output file.

    Returns:
        list: A list containing the full path of the newly created file.
    """

    output_folder = Path(output_folder)
    output_folder.mkdir(parents=True, exist_ok=True)

    try:
        with open(input_file, "r", encoding="utf-8") as file:
            content = file.read().strip()

        # Remove ``` if present
        if content.startswith("```") and content.endswith("```"):
            content = content[3:-3].strip()

        def safe_partial_escape_decode(s):
            """
            Only decode standard escapes like \\n, \\t, \\r, etc.
            Avoid decoding \\uXXXX into invalid surrogate characters.
            """
            escape_map = {
                '\\n': '\n',
                '\\t': '\t',
                '\\r': '\r',
                '\\\\': '\\',
                '\\"': '"',
                "\\'": "'"
            }
            for esc, val in escape_map.items():
                s = s.replace(esc, val)
            return s

        safe_content = safe_partial_escape_decode(content)

        # Remove any decoded surrogate characters before writing
        safe_content = ''.join(c for c in safe_content if not (0xD800 <= ord(c) <= 0xDFFF))

        output_file = output_folder / f"{cnt}"

        with open(output_file, "w", encoding="utf-8", errors="replace") as out_file:
            out_file.write(safe_content)

        return [str(output_file)]

    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
    except UnicodeDecodeError as e:
        print(f"Error: Unicode decoding issue in file '{input_file}': {e}")
    except Exception as e:
        print(f"Error processing file '{input_file}': {e}")

    return []


def smtlibify(expr_string: str) -> str:
    """
    Convert a raw SMT-like expression string into a self-contained SMT-LIB2
    snippet that includes declare-fun statements for any k!N variables, then
    wraps the original expression in (assert ...).

    This version ensures all k!N symbols are declared as (_ BitVec 8).
    """
    # 1) Find all occurrences of "k!N" in the expression
    k_pattern = r"\bk!(\d+)\b"
    k_matches = re.findall(k_pattern, expr_string)  # list of strings, e.g. ["2", "5", ...]
    unique_kids = sorted(set(k_matches), key=int)

    # 2) Declare all variables as (_ BitVec 8)
    lines = []
    for kid in unique_kids:
        lines.append(f"(declare-fun k!{kid} () (_ BitVec 8))")

    # 3) Wrap the original expression in an assert
    lines.append(f"(assert {expr_string})")

    # 4) Return the final SMT-LIB2 snippet
    return "\n".join(lines)


def is_uninterpreted_const(e: z3.ExprRef) -> bool:
    """
    Return True if `e` is a leaf, uninterpreted symbol in Python Z3
    (like 'k!2'), using top-level z3.is_app() to avoid older binding issues.
    """
    # 1) Check if e is an application
    if not z3.is_app(e):
        return False

    # 2) Check if it has no children (i.e., num_args == 0)
    if e.num_args() != 0:
        return False

    # 3) Check if the function symbol is uninterpreted
    return e.decl().kind() == z3.Z3_OP_UNINTERPRETED


def evaluateSingleExpression(expr: z3.ExprRef,
                             variable: z3.ExprRef,
                             concrete_value: z3.ExprRef) -> bool:
    # Use the top-level substitute function
    substituted_expr = z3.substitute(expr, (variable, concrete_value))
    s = z3.Solver()
    s.add(z3.Not(substituted_expr))
    return s.check() == z3.unsat


def evaluateSymbolicExpression(expr: z3.ExprRef, input_bytes: list[int]) -> bool:
    symbol_map = {}

    # Collect variables named "k!N"
    def traverse(e: z3.ExprRef):
        if is_uninterpreted_const(e):
            sym_name = e.decl().name()
            if sym_name.startswith("k!"):
                symbol_map[sym_name] = e

        # Instead of e.children(), use z3.children(e) if needed
        for child in e.children():
            traverse(child)

    traverse(expr)

    symbol_con_map = {}
    for sym_name, var_expr in symbol_map.items():
        # parse out N from "k!N"
        try:
            idx = int(sym_name[2:])
        except ValueError:
            continue

        if idx < len(input_bytes):
            bit_width = var_expr.size()  # e.g., 8
            concrete_val = z3.BitVecVal(input_bytes[idx], bit_width)
            symbol_con_map[sym_name] = concrete_val
        else:
            # print(f"Index {idx} out of range for input of size {len(input_bytes)}")
            return False

    if not symbol_con_map:
        print("No valid substitutions found.")
        return False

    # Evaluate (same logic: last substitution?s result is final)
    result = False
    for sym_name, var_expr in symbol_map.items():
        if sym_name in symbol_con_map:
            con_val = symbol_con_map[sym_name]
            result = evaluateSingleExpression(expr, var_expr, con_val)
    return result


def checkFeasiblity(expr: z3.ExprRef) -> bool:
    """
    Evaluate the feasibility of a Z3 symbolic expression by checking if it is satisfiable.

    Args:
        expr (z3.ExprRef): The Z3 symbolic expression to evaluate.

    Returns:
        bool: True if the constraints are satisfiable, False otherwise.
    """
    from z3 import Solver

    # Create a solver instance
    solver = Solver()

    # Add the symbolic expression to the solver
    solver.add(expr)

    # Check satisfiability
    result = solver.check()

    # Return True if satisfiable, otherwise False
    return result == z3.sat


def getSolutionAll(expr: z3.ExprRef) -> list[int]:
    """
    Evaluate a Z3 expression containing symbolic variables named 'k!N' (BitVec),
    and return a list of ASCII integer solutions for all such variables.

    :param expr: A Z3 expression with possible symbolic vars named like 'k!N'.
    :return:     A list of ASCII integer solutions, or an empty list if UNSAT or no suitable solutions found.
    """

    # 1) Find all variables named "k!N"
    symbol_map = {}

    def traverse(e: z3.ExprRef):
        # If 'e' is a constant and its name starts with "k!"
        if z3.is_const(e) and e.decl().kind() not in (z3.Z3_OP_TRUE, z3.Z3_OP_FALSE):
            sym_name = e.decl().name()
            if sym_name.startswith("k!"):
                symbol_map[sym_name] = e
        # Recurse on children
        for child in e.children():
            traverse(child)

    traverse(expr)

    if not symbol_map:
        print("No symbolic variables named 'k!N' found.")
        return []

    # 2) Create a solver and add 'expr' directly
    solver = z3.Solver()
    solver.add(expr)

    # 3) Solve
    check_result = solver.check()
    if check_result != z3.sat:
        print("Expression is UNSAT or unknown. No solutions.")
        return []

    # We have a SAT model
    model = solver.model()

    # 4) Sort the variables by numeric index, so "k!0" < "k!1" < ...
    sorted_by_index = sorted(
        symbol_map.keys(),
        key=lambda nm: int(nm[2:]) if nm[2:].isdigit() else 999999
    )

    # 5) Collect solutions for all variables
    solutions = []
    for sym_name in sorted_by_index:
        var_expr = symbol_map[sym_name]

        # Evaluate the variable in the model (forcing completion)
        val = model.evaluate(var_expr, model_completion=True)

        # If Z3 truly has no assignment, `val` might be None or an expression
        # like "k!57" itself.
        if val is None or val.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            # Means we didn't actually get a concrete assignment
            continue

        # If it's a bit-vector, interpret it
        if var_expr.sort().kind() == z3.Z3_BV_SORT:
            int_val = val.as_long() & 0xFF  # Ensure it's within ASCII range
            solutions.append(int_val)

    if not solutions:
        print("SAT, but model did not assign any 'k!N' variables. Returning an empty list.")
    return solutions


def getSolution(expr: z3.ExprRef) -> int:
    """
    Evaluate a Z3 expression containing a (possibly) single symbolic variable named 'k!N' (BitVec),
    and return the ASCII integer solution for the *first* such variable that is satisfiable.

    :param expr: A Z3 expression with possible symbolic vars named like 'k!N'.
    :return:     An ASCII integer solution, or -1 if UNSAT or no suitable solution found.
    """

    # 1) Find all variables named "k!N"
    symbol_map = {}

    def traverse(e: z3.ExprRef):
        # If 'e' is a constant and its name starts with "k!"
        if z3.is_const(e) and e.decl().kind() not in (z3.Z3_OP_TRUE, z3.Z3_OP_FALSE):
            sym_name = e.decl().name()
            if sym_name.startswith("k!"):
                symbol_map[sym_name] = e
        # Recurse on children
        for child in e.children():
            traverse(child)

    traverse(expr)

    if not symbol_map:
        print("No symbolic variables named 'k!N' found.")
        return -1

    # 2) Create a solver and add 'expr' directly
    solver = z3.Solver()
    solver.add(expr)

    # 3) Solve
    check_result = solver.check()
    if check_result != z3.sat:
        print("Expression is UNSAT or unknown. No solution.")
        return -1

    # We have a SAT model
    model = solver.model()

    # 4) Sort the variables by numeric index, so "k!0" < "k!1" < ...
    sorted_by_index = sorted(
        symbol_map.keys(),
        key=lambda nm: int(nm[2:]) if nm[2:].isdigit() else 999999
    )

    # 5) Return the solution for the *first* variable
    for sym_name in sorted_by_index:
        var_expr = symbol_map[sym_name]

        # Evaluate the variable in the model (forcing completion)
        val = model.evaluate(var_expr, model_completion=True)
        # If Z3 truly has no assignment, `val` might be None or an expression
        # like "k!57" itself. Usually, though, .evaluate(...) forces a concrete assignment.

        if val is None or val.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            # Means we didn't actually get a concrete assignment
            continue

        # If it's a bit-vector, interpret it
        if var_expr.sort().kind() == z3.Z3_BV_SORT:
            int_val = val.as_long() & 0xFF  # Ensure it's within ASCII range
            return int_val

        # Otherwise, just return the integer value
        try:
            return int(val.as_long())
        except Exception:
            continue

    # If no variable received a usable assignment:
    print("SAT, but model did not assign any 'k!N' variables? Returning -1.")
    return -1


def get_first_assert_expr(ast_vec: z3.AstVector): # -> z3.ExprRef | None:
    """Return the first Boolean expression found."""
    for e in ast_vec:
        if e.sort().kind() == z3.Z3_BOOL_SORT:
            return e
    return None


# handle escape sequences like \uD888
def string_to_input_bytes(s: str) -> list[int]:
    """
    Convert a Python string into a list of integer byte values.
    Decodes escape sequences like '\\n', '\\t', etc., but keeps Unicode escapes (\\uXXXX) literal.

    Args:
        s (str): The input string, which may contain escape sequences.

    Returns:
        list[int]: A list of byte values (as integers).
    """
    # Remove surrounding triple backticks
    s = s.strip()
    if s.startswith("```") and s.endswith("```"):
        s = s[3:-3].strip()

    # Only decode \n, \t, \r, etc. (NOT \uXXXX)
    escape_map = {
        '\\n': '\n',
        '\\t': '\t',
        '\\r': '\r',
        '\\\\': '\\',
        '\\"': '"',
        "\\'": "'"
    }

    def partial_escape_decode(s):
        # Apply replacements without touching \uXXXX
        for esc_seq, real_char in escape_map.items():
            s = s.replace(esc_seq, real_char)
        return s

    partially_decoded = partial_escape_decode(s)

    # Now encode to UTF-8 bytes and return list of ints
    return list(partially_decoded.encode('utf-8'))


def read_input(input_file: str) -> list[int]:
    """
    Reads a binary input file, removes leading and trailing triple backticks (```),
    interprets escape sequences as single characters, and returns the content
    as a list of integer byte values.

    Args:
        input_file (str): Path to the input file.

    Returns:
        list[int]: A list of byte values (integers) from the cleaned file content.
    """
    try:
        # Open the file in binary mode and read all bytes
        with open(input_file, "rb") as f:
            content = f.read()

        # Decode the content into a string to handle escape sequences and backticks
        content_str = content.decode("utf-8")

        # Remove leading and trailing triple backticks if present
        if content_str.startswith("```") and content_str.endswith("```"):
            content_str = content_str[3:-3].strip()

        # Handle valid escape sequences while leaving invalid ones untouched
        def safe_unicode_escape(match):
            try:
                return codecs.decode(match.group(0), "unicode_escape")
            except UnicodeDecodeError:
                return match.group(0)  # Leave invalid sequences as-is

        content_str = re.sub(r'\\u[0-9a-fA-F]{4}|\\.', safe_unicode_escape, content_str)

        # Convert the cleaned string back into bytes and return as a list of integers
        return [ord(char) for char in content_str]

    except FileNotFoundError:
        print(f"Error: Cannot open the input file '{input_file}'.")
        exit(-1)
    except Exception as e:
        print(f"Error: {e}")
        exit(-1)


def get_constraint_testcase_pairs(constraint_file, testcase_file):
    """
    Matches constraints from a JSON file with test inputs from a TXT file
    and returns a list of constraint-testinput pairs.

    Args:
        constraint_file (str): Path to the JSON file containing constraints.
        testinput_file (str): Path to the TXT file containing test inputs.

    Returns:
        list: A list of tuples where each tuple contains a constraint and its test input.
    """
    results = []

    # Load constraints from JSON file
    with open(constraint_file, "r", encoding="utf-8") as f:
        constraints = json.load(f)

    # Load test inputs from TXT file
    testcases = {}
    with open(testcase_file, "r", encoding="utf-8") as f:
        for line in f:
            if "---" in line:
                key, value = line.split("---", 1)
                testcases[key.strip()] = value.strip()

    # Match constraints with test inputs
    for key, constraint in constraints.items():
        if key in testcases:
            testcase = testcases[key]
            results.append((constraint, testcase))

    return results


def get_constraint_testcase_pair_by_key(key, constraint_file, testcase_file):
    """
    Matches a specific constraint from a JSON file with a test input from a TXT file
    and returns the matching constraint-testinput pair.

    Args:
        constraint_file (str): Path to the JSON file containing constraints.
        testcase_file (str): Path to the TXT file containing test inputs.
        key (str): The key to match between the constraints and test inputs.

    Returns:
        tuple: A tuple containing the matching constraint and its test input, or None if no match is found.
    """
    # Load constraints from JSON file
    with open(constraint_file, "r", encoding="utf-8") as f:
        constraints = json.load(f)

    # Load test inputs from TXT file
    testcases = {}
    with open(testcase_file, "r", encoding="utf-8") as f:
        for line in f:
            if "---" in line:
                key_part, value = line.split("---", 1)
                testcases[key_part.strip()] = value.strip()

    # Match the specific key
    if key in constraints and key in testcases:
        return constraints[key], testcases[key]

    return None


def mark_node_in_tree(key: str, json_file: str) -> bool:
    """
    Search the JSON tree for a node with the specified key and mark its attributes.
    - Set "tk" to 1 and increment "vc".
    - Return True if any node had "tk: 0" before marking; otherwise, return False.

    Args:
        key (str): A string in the format "node_name_cs_value_bi_value".
        json_file (str): The path to the JSON file to parse and search.

    Returns:
        bool: True if any node had "tk: 0" before marking, False otherwise.
    """
    # Ensure the file exists
    if not os.path.exists(json_file):
        raise FileNotFoundError(f"The file '{json_file}' does not exist in the current directory.")

    # Load the JSON tree from the file
    try:
        with open(json_file, 'r') as file:
            json_tree = json.load(file)
    except json.JSONDecodeError:
        # Malformed JSON, skip processing # TODO why?
        return False


    # Extract the node name, cs value, and bi value from the key
    try:
        node_name, cs_value, bi_value = key.rsplit("_cs_", 1)[0], key.rsplit("_cs_", 1)[1].rsplit("_bi_", 1)[0], key.rsplit("_bi_", 1)[1]
        cs_value = int(cs_value)
        bi_value = int(bi_value)
    except ValueError:
        raise ValueError("Key format is invalid. Expected format: 'node_name_cs_value_bi_value'")

    any_tk_was_zero = False  # To track if any node had "tk: 0"

    def traverse(node):
        nonlocal any_tk_was_zero

        # Ensure the node is a dictionary
        if not isinstance(node, dict):
            return False

        # Check if the current node matches
        if node.get("loc") == node_name and node.get("cs") == cs_value and node.get("br") == bi_value:
            if node.get("tk", 0) == 0:
                any_tk_was_zero = True  # Found a node with "tk: 0"
            # Mark the node's attributes
            node["tk"] = 1
            node["vc"] = node.get("vc", 0) + 1
            return True

        # Recursively check children
        for child in node.get("ch", []):
            if traverse(child):
                return True

        return False

    # Start traversal from the root
    root_node = json_tree.get("root", {})
    found = traverse(root_node)

    # Write back to the file if changes were made
    if found:
        with open(json_file, 'w') as file:
            json.dump(json_tree, file, indent=2)

    # Return True if any "tk: 0" was found and marked, otherwise False
    return any_tk_was_zero


def extract_names_from_json(file_path):
    """
    Extracts all keys (representing "name" fields) from the provided JSON file,
    stores them in a list, and prints them.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        list: A list of all extracted keys.
    """
    try:
        # Read the JSON file
        with open(file_path, 'r') as file:
            data = json.load(file)

        # Extract all keys (names)
        name_list = list(data.keys())

        # Print the list
        #print("Extracted Names:")
        #for name in name_list:
        #    print(name)

        return name_list

    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return []


def is_folder_empty(folder_path):
    return not any(Path(folder_path).iterdir())


def check_string_in_file(string_to_check, file_path):
    """
    Check if a given string exists in a file.

    Args:
        string_to_check (str): The string to search for in the file.
        file_path (str or Path): The path to the file.

    Returns:
        bool: True if the string exists in the file, False otherwise.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if string_to_check in line:
                    return True
        return False
    except FileNotFoundError:
        print(f"Error: The file {file_path} does not exist.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False


def count_lines_with_dash(file_path):
    """
    Counts how many lines in the given text file contain the string "---".

    Args:
        file_path (str): Path to the text file.

    Returns:
        int: The number of lines containing "---".
    """
    count = 0
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            for line in file:
                if "---" in line:
                    count += 1
    except FileNotFoundError:
        print(f"Error: The file '{file_path}' does not exist.")
    except Exception as e:
        print(f"An error occurred: {e}")

    return count


def save_cleaned_content_to_file(folder_path, input_string):
    """
    Cleans and saves a string to a file named 'seed' in the specified folder.

    Args:
        folder_path (str): The path to the folder where the cleaned content should be saved.
        input_string (str or None): The string with possible leading/trailing backticks and format labels.

    Returns:
        None
    """
    # Define possible format labels
    format_labels = ["json", "xml", "sql", "uri", "javascript"]

    # Ensure input_string is not None
    if input_string is None:
        print("Warning: input_string is None, defaulting to an empty string.")
        input_string = ""

    # Ensure the folder exists
    os.makedirs(folder_path, exist_ok=True)

    # Construct the file path for "seed"
    file_path = os.path.join(folder_path, "seed")

    # Strip surrounding whitespace or newlines
    input_string = input_string.strip()

    # Remove any leading backticks with or without format label
    if input_string.startswith("```"):
        for label in format_labels:
            if input_string.startswith(f"```{label}"):
                input_string = input_string[len(f"```{label}"):].strip()
                break
        else:
            input_string = input_string[3:].strip()

    # Remove trailing backticks if they exist
    if input_string.endswith("```"):
        input_string = input_string[:-3].strip()

    # Save the cleaned string to the "seed" file
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(input_string)
        print(f"Content saved to {file_path}")
    except Exception as e:
        print(f"Failed to save content: {e}")


def clean_content_from_file(file_path):
    """
    Cleans and returns a string from the specified file.

    Args:
        file_path (str): Path to the file containing the string.

    Returns:
        str: The cleaned string with possible leading/trailing backticks and format labels removed.
    """
    import os

    # Define possible format labels
    format_labels = ["json", "xml", "sql", "uri", "javascript"]

    try:
        # Read the content from the file
        with open(file_path, "r", encoding="utf-8") as file:
            input_string = file.read().strip()

        # Remove any leading backticks with or without format label
        if input_string.startswith("```"):
            # Check for format label
            for label in format_labels:
                if input_string.startswith(f"```{label}"):
                    input_string = input_string[len(f"```{label}"):].strip()
                    break
            else:
                # If no format label, just remove the leading backticks
                input_string = input_string[3:].strip()

        # Remove trailing backticks if they exist
        if input_string.endswith("```"):
            input_string = input_string[:-3].strip()

        return input_string

    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return ""
    except Exception as e:
        print(f"Error processing the file: {e}")
        return ""


def find_newly_taken_nodes(tree_file, last_tree_file):
    """
    Compares two JSON files to find nodes that are newly taken.

    Args:
        tree_file (str or Path): Path to the current global-tree.json file.
        last_tree_file (str or Path): Path to the last global-tree-last.json file.

    Returns:
        list: A list of `loc` values of nodes that are newly taken.
    """
    def find_nodes(tree, last_tree, newly_taken, path="root"):
        """
        Recursively compare nodes and find newly taken ones.

        Args:
            tree (dict): Current tree node.
            last_tree (dict): Last tree node.
            newly_taken (list): Accumulator for newly taken node loc values.
            path (str): Path to locate the current node in debugging.
        """
        if "loc" in tree and "tk" in tree:
            current_tk = tree.get("tk", 0)
            last_tk = last_tree.get("tk", 0) if last_tree else 0

            if current_tk == 1 and last_tk == 0:
                newly_taken.append(tree["loc"])

        # Recursively process child nodes
        for current_child, last_child in zip(tree.get("ch", []), last_tree.get("ch", []) if last_tree else []):
            find_nodes(current_child, last_child, newly_taken)

        # Handle cases where new children exist in the current tree but not in the last tree
        for current_child in tree.get("ch", [])[len(last_tree.get("ch", []) if last_tree else []):]:
            find_nodes(current_child, {}, newly_taken)

    try:
        # Load the JSON files
        with open(tree_file, "r", encoding="utf-8") as f:
            current_tree = json.load(f)

        with open(last_tree_file, "r", encoding="utf-8") as f:
            last_tree = json.load(f)

        newly_taken = []
        find_nodes(current_tree.get("root", {}), last_tree.get("root", {}), newly_taken)
        return newly_taken

    except Exception as e:
        print(f"Error processing files: {e}")
        return []


def find_untaken_nodes(tree_file, untaken_branches):
    """
    Traverses the tree and updates the global 'untaken_branches' dictionary.
    Each key is a branch name (loc) with tk=0, and the value is the count of occurrences.
    Any branch that appears more than 5 times is removed from the dictionary.
    
    Args:
        tree_file (str or Path): Path to the JSON tree file.
    """
    # global untaken_branches

    def traverse_tree(node):
        if node.get("tk") == 0 and node.get("br") != -1:
            loc = node.get("loc")
            if loc:
                count = untaken_branches.get(loc, 0) + 1
                if count > 3:
                    untaken_branches.pop(loc, None)  # remove over-threshold
                else:
                    untaken_branches[loc] = count
        for child in node.get("ch", []):
            traverse_tree(child)

    try:
        with open(tree_file, "r", encoding="utf-8") as file:
            tree = json.load(file)
        traverse_tree(tree.get("root", {}))
    except Exception as e:
        print(f"Error processing the tree file: {e}")


def simplify_keys_in_json_with_mapping(file_path):
    """
    Simplifies the keys in a JSON file by extracting all numbers and concatenating them as a unique key.
    Returns a dictionary where the key is the new name and the value is the old name.

    Args:
        file_path (str or Path): Path to the JSON file to process.

    Returns:
        dict: A mapping of new keys to old keys.
    """
    file_path = Path(file_path)

    try:
        # Load the JSON content
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Create a new dictionary for simplified keys and a mapping dict
        simplified_data = {}
        key_mapping = {}

        for old_key, value in data.items():
            # Extract all numbers from the key and join them with underscores
            new_key = "_".join(re.findall(r'\d+', old_key))
            simplified_data[new_key] = value
            key_mapping[new_key] = old_key

        # Write the updated JSON back to the file
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(simplified_data, file, indent=4)

        print(f"Keys in {file_path} have been simplified and saved.")

        return key_mapping

    except Exception as e:
        print(f"Error processing the file: {e}")
        return {}


def execute_every_n_seconds(target_function, duration, *args, **kwargs):
    """
    Executes a target function every `duration` seconds.

    Args:
        target_function (callable): The function to be executed.
        duration (float): The interval in seconds between function executions.
        *args: Positional arguments to pass to the target function.
        **kwargs: Keyword arguments to pass to the target function.
    """
    last_execution_time = 0  # Initial time

    while True:
        current_time = time.time()  # Get the current time as a floating-point number

        # Check if `duration` seconds have passed since the last execution
        if current_time - last_execution_time >= duration:
            target_function(*args, **kwargs)  # Call the target function
            last_execution_time = current_time  # Update the last execution time

        # Sleep for a short duration to prevent busy waiting
        time.sleep(0.1)



def update_running_log(file_path, file_exe, args, duration=0, gpt_invocation_cnt=0, gpt_solving_time=0, gpt_seed_generation_cnt=0,
                  gpt_history_update_cnt=0, total_pc_cnt=0, gpt_generated_testcases_cnt=0, gpt_missed_testcases_cnt=0,
                  valid_testcases_cnt=0, invalid_testcases_cnt=0, is_not_interesting_cnt=0, prompt_token_cnt=0):
    """
    Updates the file with the current record, including the timestamp and provided values in JSON format.

    Args:
        file_path (str): The path to the file where records are stored.
        gpt_invocation_cnt (int): Count of GPT invocations.
        gpt_solving_time (float): Time spent solving with GPT (in seconds).
        gpt_seed_generation_cnt (int): Count of GPT seed generations.
        gpt_history_update_cnt (int): Count of GPT history updates.
        total_pc_cnt (int): Total path constraints count.
        gpt_generated_testcases_cnt (int): Total generated test cases count by GPT.
        gpt_missed_testcases_cnt (int): Total missed test cases count by GPT.
        valid_testcases_cnt (int): Valid test cases count.
        invalid_testcases_cnt (int): Invalid test cases count.
    """
    # Get the current timestamp
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a dictionary for the record
    record = {
        "executed file": file_exe,
        "duration": duration,
        "gpt_invocation_cnt": str(gpt_invocation_cnt),
        "gpt_solving_time": str(gpt_solving_time),
        "gpt_seed_generation_cnt": str(gpt_seed_generation_cnt),
        "gpt_history_update_cnt": str(gpt_history_update_cnt),
        "total_pc_cnt": str(total_pc_cnt),
        "gpt_generated_testcases_cnt": str(gpt_generated_testcases_cnt),
        "gpt_missed_testcases_cnt": str(gpt_missed_testcases_cnt),
        "valid_solving_cnt": str(valid_testcases_cnt),
        "invalid_solving_cnt": str(invalid_testcases_cnt),
        "is_not_interesting_cnt": str(is_not_interesting_cnt),
        "prompt_token_cnt": str(prompt_token_cnt),
    }
    
    try:
        # execute_every_n_seconds(report_coverage, 60, args) # TODO need test
        # Append the new record as a single line to the file
        with open(file_path, "a", encoding="utf-8") as file:
            print("+++ LOG: ", record)
            file.write(json.dumps(record) + "\n")

    except Exception as e:
        print(f"Error updating the record: {e}")


def clear_folder(folder_path: str):
    """
    Clear all files and subfolders in the specified folder.

    Args:
        folder_path (str): The path to the folder to be cleared.

    Raises:
        FileNotFoundError: If the specified folder does not exist.
        PermissionError: If the script does not have permission to delete files in the folder.
    """
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"The folder '{folder_path}' does not exist.")

    # Iterate through all files and subdirectories in the folder
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                # Remove files or symbolic links
                os.unlink(file_path)
            elif os.path.isdir(file_path):
                # Remove directories recursively
                shutil.rmtree(file_path)
        except Exception as e:
            raise PermissionError(f"Failed to delete '{file_path}'. Reason: {e}")


# the version handles empth file
def load_json_to_dict(file_path):
    """
    Load a JSON file and return its contents as a dictionary. If the file is missing, empty,
    or contains invalid JSON, it will return an empty dictionary `{}` instead of raising an error.

    Args:
        file_path (str): The path to the JSON file.

    Returns:
        dict: The JSON content as a Python dictionary, or an empty dictionary `{}` if an error occurs.
    """
    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Warning: The file '{file_path}' does not exist. Returning empty dictionary.")
        return {}

    # Check if the file is empty
    if os.path.getsize(file_path) == 0:
        print(f"Warning: JSON file '{file_path}' is empty. Returning empty dictionary.")
        return {}

    # Try to load the JSON file
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read().strip()  # Remove leading/trailing whitespace

            # Handle files containing only whitespace
            if not content:
                print(f"Warning: JSON file '{file_path}' contains only whitespace. Returning empty dictionary.")
                return {}

            return json.loads(content)  # Properly parse JSON

    except json.JSONDecodeError as e:
        print(f"Warning: Invalid JSON content in '{file_path}': {e}. Returning empty dictionary.")
        return {}

    except Exception as e:
        print(f"Warning: Unexpected error while reading '{file_path}': {e}. Returning empty dictionary.")
        return {}


def replace_bytes_with_holes_and_truncate_from_json(constant_str, json_file):
    """
    Replace bytes at 'k!n' positions with placeholders, and convert common escape sequences
    like '\\x0A' to real characters like '\n'. Avoid decoding \\uXXXX.

    Args:
        constant_str (str): A string containing placeholders like 'k!n'.
        json_file (str): Path to a JSON file mapping byte indices to characters.

    Returns:
        str: Modified string with [k!n] inserted and truncated, escape-decoded.
    """
    try:
        # print("constant_str: ", constant_str)
        with open(json_file, "r", encoding="utf-8") as file:
            data = json.load(file)

        # Reconstruct the full string from indexed characters
        max_index = max(int(k) for k in data.keys())
        raw_chars = [data.get(str(i), '') for i in range(max_index + 1)]
        raw_input_str = ''.join(raw_chars)

        # print("raw_input_str : ", raw_input_str)
        # Replace \\xXX hex escapes with actual characters (e.g., \x0A → newline)
        def decode_visible_escapes(s):
            # Decode \xXX manually without touching \uXXXX
            def decode_match(match):
                hex_value = match.group(1)
                return chr(int(hex_value, 16))
            # Replace all \xHH
            return re.sub(r'\\x([0-9A-Fa-f]{2})', decode_match, s)

        input_str = decode_visible_escapes(raw_input_str)

        # Find all placeholder indices like k!17
        matches = re.findall(r'k!(\d+)', constant_str)
        if not matches:
            raise ValueError("No valid 'k!n' patterns found in the constant string.")

        indices = sorted(set(int(n) for n in matches))
        largest_n = max(indices)

        if largest_n >= len(input_str):
            raise IndexError(f"Index {largest_n} is out of bounds for input string length {len(input_str)}.")

        # Replace the k!n bytes with [k!n]
        result = list(input_str)
        for n in indices:
            if n < len(result):
                result[n] = f"[k!{n}]"

        # Return string up to the largest replaced index + 1, plus [xxx] marker
        return ''.join(result[:largest_n + 1]) + "[xxx]"

    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
        # exit(1)

    return ""


def store_input_bytes_as_string(inputs, file_path="input-bytes-after-solving.json"):
    """
    Generate a JSON file where keys are the order of the inputs and values are the string representation of the inputs.

    Args:
        inputs (list[int]): A list of input byte values (integers).
        file_path (str): The path where the JSON file will be saved.

    Returns:
        None
    """
    # Create a dictionary with numeric order as keys and characters as values
    ordered_data = {str(i): chr(byte) for i, byte in enumerate(inputs)}

    # Write the dictionary to a JSON file
    with open(file_path, "w", encoding="utf-8") as json_file:
        json.dump(ordered_data, json_file, indent=4)
    print(f"JSON file successfully created: {file_path}")


def list_files_in_folder(folder_path):
    """
    Lists all the files in the specified folder.

    Args:
        folder_path (str): Path to the folder.

    Returns:
        list: A list of filenames in the folder.

    Raises:
        FileNotFoundError: If the folder does not exist.
        NotADirectoryError: If the path is not a directory.
    """
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"The folder '{folder_path}' does not exist.")

    if not os.path.isdir(folder_path):
        raise NotADirectoryError(f"The path '{folder_path}' is not a directory.")

    # List all files in the folder
    files = [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]
    return files


def get_values_from_jsons(key: str, json_file_1: str, json_file_2: str):
    """
    Retrieves the value for a given key from two JSON files and prints the values.

    Args:
        key (str): The key to search for in the JSON files.
        json_file_1 (str): Path to the first JSON file.
        json_file_2 (str): Path to the second JSON file.

    Returns:
        tuple: A tuple containing the values from both JSON files (value1, value2).
               Returns None for a file if the key is not found or the file cannot be read.
    """
    def get_value_from_json(key: str, json_file: str):
        try:
            with open(json_file, "r", encoding="utf-8") as file:
                data = json.load(file)
                return data.get(key, None)
        except FileNotFoundError:
            print(f"Error: File '{json_file}' not found.")
        except json.JSONDecodeError:
            print(f"Error: Could not decode JSON file '{json_file}'.")
        return None

    # Get values from both JSON files
    value1 = get_value_from_json(key, json_file_1)
    value2 = get_value_from_json(key, json_file_2)

    print(f"Value for key '{key}' in {json_file_1}: {value1}")
    print(f"Value for key '{key}' in {json_file_2}: {value2}")

    return value1, value2

def extract_unique_keys(input_string: str) -> list[str]:
    """
    Extracts all unique 'k!n' keys from the input string, where n is the number after 'k!'.

    Args:
        input_string (str): The input string containing 'k!n' patterns.

    Returns:
        list[str]: A list of unique 'n' values as strings.
    """
    # Find all occurrences of the pattern 'k!n' using a regular expression
    matches = re.findall(r'k!(\d+)', input_string)
    
    # Return unique values as a sorted list
    return sorted(set(matches))


def _interpret_ascii_token(token_str: str) -> str:
    """
    Interpret the given string as a single 8-bit ASCII character if possible.

    1) If token_str is a numeric string 0..255 (e.g. "10"), interpret that as chr(10).
    2) If token_str == r"\n", interpret as an actual newline character "\n".
    3) If token_str == r"\t", interpret as an actual tab character "\t".
    4) Otherwise, return token_str as is (assuming it's already a single ASCII character).

    Examples:
      - "65"   -> "A"
      - "10"   -> "\n"
      - r"\n"  -> "\n"
      - r"\t"  -> "\t"
      - "A"    -> "A"
    """
    # 1) Check if token_str is numeric within [0..255]
    try:
        code = int(token_str)
        if 0 <= code <= 255:
            return chr(code)
    except ValueError:
        pass  # Not numeric, so continue

    # 2) Check common escaped sequences as raw strings
    if token_str == r"\n":
        return "\n"
    if token_str == r"\t":
        return "\t"

    # 3) Otherwise, leave as-is
    return token_str


def remove_xxx_and_split(marked_string: str):
    # remove all [xxx] from the marked string:
    s = marked_string.replace("[xxx]", "")
    # now split on [k!\d+]
    return re.split(r"\[k!\d+\]", s)


def fix_format_issue(input_string):
    """
    Fix format issues in a string by ensuring the first three characters (if they are `[`, `{`, or `"`)
    are properly matched. If they are not these characters, do not modify the string.

    Args:
        input_string (str): The input string to fix.

    Returns:
        str: The fixed string with matching symbols or the original string if no changes are needed.
    """
    # Define matching pairs
    matching_pairs = {
        '[': ']',
        '{': '}',
        '"': '"'
    }

    # Check if the first three characters are `[`, `{`, or `"`
    first_three = input_string[:3]
    if not any(char in matching_pairs for char in first_three):
        return input_string  # No changes needed

    # Fix the first three characters
    stack = []
    for char in first_three:
        if char in matching_pairs:
            stack.append(matching_pairs[char])

    # Append the matching characters to the end of the string
    fixed_string = input_string + ''.join(stack)
    return fixed_string


def validate_and_refine_string_for_all(tokens: list[int], marked_string: str, gpt_string: str) -> dict:
    """
    Validate and refine a GPT-generated string based on the given tokens and marked template.

    :param tokens:        A list of ASCII codes (integers) to replace markers like [k!<number>].
    :param marked_string: The marked template containing [k!<number>] and possibly [xxx].
    :param gpt_string:    The GPT-generated string to validate and refine.
    :return: A dictionary with:
               - "isValid": bool => True if GPT string matches perfectly; False otherwise.
               - "refinedString": str => The final output after either confirming or fixing.
    """

    import re
    import codecs

    def ascii_to_char(ascii_code: int) -> str:
        """Convert an ASCII code to its character equivalent."""
        try:
            return chr(ascii_code)
        except ValueError:
            print(f"Invalid ASCII code: {ascii_code}")
            return ""

    def normalize_string(input_string: str) -> str:
        """
        Normalize a string by decoding escape sequences and ensuring consistent formatting.
        Handles invalid escape sequences gracefully.
        """
        import codecs

        try:
            # Replace invalid escape sequences (like \x) with their raw representation
            input_string = codecs.decode(input_string, 'unicode_escape')
        except UnicodeDecodeError as e:
            print(f"Error decoding escape sequences: {e}")
            # Handle invalid escape sequences by escaping backslashes
            input_string = input_string.encode('utf-8').decode('unicode_escape', errors='backslashreplace')
        return input_string


    def remove_backticks_and_code_type(input_string: str) -> str:
        """Remove matching leading/trailing backticks and optional code type annotations like `json`."""
        if input_string.startswith("```") and input_string.endswith("```"):
            stripped = input_string[3:-3].strip()
            lines = stripped.split("\n", 1)
            if len(lines) > 1 and lines[0] in {"json", "xml", "sql", "javascript", "uri"}:
                stripped = lines[1]
            return stripped.strip()
        return input_string.strip()

    def replace_mismatch(gpt_string: str, position: int, token_char: str) -> str:
        """Replace the mismatched part of gpt_string with the token_char."""
        print(f"Replacing mismatch at position {position} with '{token_char}'")
        return gpt_string[:position] + token_char + gpt_string[position + 1:]

    # Normalize and clean the marked string
    try:
        marked_string = normalize_string(marked_string.replace("[xxx]", ""))
    except Exception as e:
        print(f"Error normalizing marked string: {e}")
        return {"isValid": False, "refinedString": ""}

    # Clean the GPT-generated string
    try:
        gpt_string = remove_backticks_and_code_type(gpt_string)
        gpt_string = normalize_string(gpt_string)
    except Exception as e:
        print(f"Error normalizing GPT string: {e}")
        return {"isValid": False, "refinedString": ""}

    # Split the cleaned marked string by any [k!<number>] pattern
    sub_strings = re.split(r"\[k!(\d+)\]", marked_string)

    # Extract all `[k!n]` indices and find the maximum
    indices = [int(n) for n in sub_strings[1::2]]
    max_index = max(indices, default=-1)

    # Validate and match tokens for previous markers
    position = 0
    token_index = 0
    refined_string = ""

    for i in range(0, len(sub_strings), 2):
        fixed_part = sub_strings[i]
        refined_string += fixed_part

        # Check for token replacement
        if i + 1 < len(sub_strings):
            token_num = int(sub_strings[i + 1])  # Get the index from [k!<number>]

            if token_index >= len(tokens):
                print("Not enough tokens provided for all [k!n] markers.")
                return {"isValid": False, "refinedString": refined_string}

            token_char = ascii_to_char(tokens[token_index])
            token_index += 1

            refined_string += token_char

    return {"isValid": True, "refinedString": refined_string}


def validate_and_refine_string(token: int, marked_string: str, gpt_string: str) -> dict:
    """
    Validate and refine a GPT-generated string based on the given token and marked template.

    :param token:         The expected ASCII code (integer) to replace markers like [k!<number>].
    :param marked_string: The marked template containing [k!<number>] and possibly [xxx].
    :param gpt_string:    The GPT-generated string to validate and refine.
    :return: A dictionary with:
               - "isValid": bool => True if GPT string matches perfectly; False otherwise.
               - "refinedString": str => The final output after either confirming or fixing.
    """

    def ascii_to_char(ascii_code: int) -> str:
        """Convert an ASCII code to its character equivalent."""
        try:
            return chr(ascii_code)
        except ValueError:
            print(f"Invalid ASCII code: {ascii_code}")
            return ""

    def normalize_string(input_string: str) -> str:
        """
        Normalize a string by decoding escape sequences and ensuring consistent formatting.
        Handles invalid escape sequences gracefully.
        """
        import codecs

        try:
            # Replace invalid escape sequences (like \x) with their raw representation
            input_string = codecs.decode(input_string, 'unicode_escape')
        except UnicodeDecodeError as e:
            print(f"Error decoding escape sequences: {e}")
            # Handle invalid escape sequences by escaping backslashes
            input_string = input_string.encode('utf-8').decode('unicode_escape', errors='backslashreplace')
        return input_string

    def remove_backticks_and_code_type(input_string: str) -> str:
        """Remove matching leading/trailing backticks and optional code type annotations like `json`."""
        if input_string.startswith("```") and input_string.endswith("```"):
            stripped = input_string[3:-3].strip()
            lines = stripped.split("\n", 1)
            if len(lines) > 1 and lines[0] in {"json", "xml", "sql", "javascript", "uri"}:
                stripped = lines[1]
            return stripped.strip()
        return input_string.strip()

    def replace_mismatch(gpt_string: str, position: int, token_char: str) -> str:
        """Replace the mismatched part of gpt_string with the token_char."""
        print(f"Replacing mismatch at position {position} with '{token_char}'")
        return gpt_string[:position] + token_char + gpt_string[position + 1:]

    # Convert token to its character equivalent
    token_char = ascii_to_char(token)

    # Normalize and clean the marked string
    marked_string = normalize_string(marked_string.replace("[xxx]", ""))

    # Clean the GPT-generated string
    gpt_string = remove_backticks_and_code_type(gpt_string)
    gpt_string = normalize_string(gpt_string)

    # Split the cleaned marked string by any [k!<number>] pattern
    sub_strings = re.split(r"\[k!(\d+)\]", marked_string)

    # Validate the GPT string
    position = 0
    for i in range(0, len(sub_strings), 2):
        fixed_part = sub_strings[i]

        # Check for fixed substring match
        if not gpt_string[position:].startswith(fixed_part):
            gpt_string = replace_mismatch(gpt_string, position, token_char)
            return {
                "isValid": False,
                "refinedString": gpt_string
            }

        position += len(fixed_part)

        # Check for token character at the expected position
        if i + 1 < len(sub_strings):
            token_index = int(sub_strings[i + 1])  # Get the index from [k!<number>]

            # Validate position bounds
            if position >= len(gpt_string):
                print("GPT string too short. Replacing token.")
                refined_string = marked_string.replace(f"[k!{token_index}]", token_char).replace("[xxx]", "")
                return {
                    "isValid": False,
                    "refinedString": refined_string
                }

            # Compare the actual character in GPT string with the token character
            if gpt_string[position] != token_char:
                print("Token mismatch:")
                print("Expected Token Char:", repr(token_char))
                print("Actual GPT Char:", repr(gpt_string[position]))
                gpt_string = replace_mismatch(gpt_string, position, token_char)
                return {
                    "isValid": False,
                    "refinedString": gpt_string
                }

            position += 1

    # If we reach here, everything matched; clean and save the GPT string
    return {
        "isValid": True,
        "refinedString": gpt_string
    }


def refine_string(tokens: list[int], marked_string: str, json_file_path: str) -> str:
    """
    Replace bytes in positions extracted from [k!n] markers with values from `tokens`,
    and reconstruct the string based on the original content from the JSON file.

    Args:
        tokens (list[int]): ASCII byte values to use as replacements.
        marked_string (str): A string containing `[k!n]` placeholders and `[xxx]`.
        json_file_path (str): JSON file mapping positions to character values (as strings).

    Returns:
        str: Refined string with markers replaced.
    """

    def decode_byte_value(val: str) -> str:
        """Decode escape-like strings such as '\\x0A' into actual characters."""
        return re.sub(r'\\x([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), val)

    # Step 1: Load original character mapping from file
    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            char_map = json.load(f)
    except Exception as e:
        raise ValueError(f"Failed to load JSON: {e}")

    # Step 2: Decode all characters in order
    max_index = max(int(k) for k in char_map.keys())
    chars = [decode_byte_value(char_map.get(str(i), '')) for i in range(max_index + 1)]

    # Step 3: Extract all [k!n] markers
    marker_indices = [int(m) for m in re.findall(r'\[k!(\d+)\]', marked_string)]

    # if len(tokens) < len(marker_indices):
    #     raise ValueError(f"Expected {len(marker_indices)} tokens, but only got {len(tokens)}.")

    # Step 4: Apply replacements using tokens
    for i, idx in enumerate(marker_indices):
        if 0 <= idx < len(chars):
            chars[idx] = chr(tokens[i])
        else:
            raise IndexError(f"Index k!{idx} is out of bounds for input length {len(chars)}")
        break # TODO should support multipule replacement?

    # Step 5: Reconstruct and return the full string
    return ''.join(chars)


def _write_back(file_path: str, content: str) -> None:
    """
    Helper function to write content back to the same file.
    """
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(content)


def copy_file_to_folder(file_path, folder_path):
    """
    Copies a file to a specified folder.

    Args:
        file_path (str or Path): The path of the file to be copied.
        folder_path (str or Path): The target folder where the file will be copied.

    Returns:
        str: The path to the copied file in the target folder.
    """
    file_path = Path(file_path)
    folder_path = Path(folder_path)

    if not file_path.exists():
        raise FileNotFoundError(f"The file '{file_path}' does not exist.")
    if not folder_path.exists():
        folder_path.mkdir(parents=True, exist_ok=True)

    # Construct the destination path
    destination_path = folder_path / file_path.name

    # Copy the file to the target folder
    shutil.copy2(file_path, destination_path)

    return str(destination_path)


def check_and_add_string(new_string):
    """Check if a string is in the set and add it if not, with special case handling."""
    # Special case: If the string contains "[k!0]", always return True
    if "[k!0]" in new_string:
        print(f"Special case detected in '{new_string}'. Returning True.")
        return True

    # Normal case: Check and add to the set
    if new_string in global_set:
        print(f"'{new_string}' is already in the set.")
        return False  # Indicates the string was already present
    else:
        global_set.add(new_string)
        print(f"Added '{new_string}' to the set.")
        return True  # Indicates the string was added


def maintain_top_10_history_coverage(record_list, record, key):
    """
    Maintain a list of up to 10 records, keeping the latest updated record at the top.

    Args:
        record_list (deque): A deque to store records.
        record (str): The new record to add or update.
        key (str): A key to identify if the record is already in the list.

    Returns:
        deque: The updated deque containing up to 10 records.
    """
    if not isinstance(record_list, deque):
        raise TypeError("record_list must be a deque.")

    # Check if the record with the same key already exists
    for i, existing_record in enumerate(record_list):
        if key in existing_record:
            # Update the record and move it to the top
            record_list.remove(existing_record)
            break

    # Add the new record to the top
    record_list.appendleft(record)

    # Ensure the list only keeps the latest 10 records
    if len(record_list) > 10:
        record_list.pop()

    return record_list


class DeepSeekChatSession:
    """
    A class to manage a DeepSeek chat session with global instructions.
    """

    def __init__(self, args, api_key):
        self.api_key = api_key
        self.model = args["model"]
        cot_prompt = ""
        
        if args["format"] == "JSON":
            cot_prompt = COTPRMOPT["JSON"]
        elif args["format"] == "XML":
            cot_prompt = COTPRMOPT["XML"]
        elif args["format"] == "SQL":
            cot_prompt = COTPRMOPT["SQL"]
        elif args["format"] == "JavaScript":
            cot_prompt = COTPRMOPT["JavaScript"]
        
        self.messages = [{"role": "system", "content": cot_prompt}]
        
        self.client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com")

    def add_message(self, role, content):
        """
        Add a message to the conversation history.
        """
        self.messages.append({"role": role, "content": content})

    def send_message(self, user_message):
        """
        Send a message to the DeepSeek API and get a response.
        """
        self.add_message("user", user_message)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                stream=False
            )
            
            assistant_message = response.choices[0].message.content
            token_usage = response.usage.prompt_tokens if hasattr(response, "usage") else 0
            
            self.add_message("assistant", assistant_message)
            return {"response": assistant_message, "token_usage": token_usage}
        
        except requests.exceptions.Timeout:
            return {"response": None, "error": "Request timed out. Please try again later."}
        except requests.exceptions.ConnectionError:
            time.sleep(30)
            return {"response": None, "error": "Network connection error. Retrying after 30 seconds."}
        except requests.exceptions.HTTPError as e:
            return {"response": None, "error": f"HTTP error occurred: {e}"}
        except requests.exceptions.RequestException as e:
            return {"response": None, "error": f"Request error: {e}"}
        except ValueError:
            return {"response": None, "error": "Invalid JSON response from API."}
        except Exception as e:
            return {"response": None, "error": f"Unexpected error: {e}"}


class DeepSeekChatSessionForSeed:
    """
    A class to manage a DeepSeek chat session for seed generation with global instructions.
    """

    def __init__(self, args, api_key):
        model= args["model"]
        self.api_key = api_key
        self.model = model
        self.messages = [
            {
                "role": "system",
                "content": (
                    "You are a powerful seed generator and know many test inputs for different formats (e.g., JSON/XML/URI/SQL/JavaScript). "
                    "You will need to generate seed test inputs based on the following requirements:\n"
                    "1. When the testing is just started, just randomly generate valid input (e.g., buggy inputs from code history).\n"
                    "2. When the testing is running, you will need to (1) generate valid test inputs (e.g., buggy inputs from code history) based on the extra information "
                    "(history coverage and uncovered branches) I gave to you; (2) generate totally different test input (e.g., buggy inputs from code history) every time; "
                    "(3) try your best to infer dependence based on function names (each branch record consists of filename_functionname_loc_branchtype).\n"
                    "3. Please just output the valid test input in ```...``` without any explanations or extra chars."
                )
            }
        ]
        
        self.client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com")

    def add_message(self, role, content):
        """
        Add a message to the conversation history.
        """
        self.messages.append({"role": role, "content": content})

    def send_message(self, user_message):
        """
        Send a message to the DeepSeek API and get a response.
        """
        self.add_message("user", user_message)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                stream=False
            )
            
            assistant_message = response.choices[0].message.content
            token_usage = response.usage.prompt_tokens if hasattr(response, "usage") else 0
            
            self.add_message("assistant", assistant_message)
            return {"response": assistant_message, "token_usage": token_usage}
        
        except requests.exceptions.Timeout:
            return {"response": None, "error": "Request timed out. Please try again later."}
        except requests.exceptions.ConnectionError:
            time.sleep(30)
            return {"response": None, "error": "Network connection error. Retrying after 30 seconds."}
        except requests.exceptions.HTTPError as e:
            return {"response": None, "error": f"HTTP error occurred: {e}"}
        except requests.exceptions.RequestException as e:
            return {"response": None, "error": f"Request error: {e}"}
        except ValueError:
            return {"response": None, "error": "Invalid JSON response from API."}
        except Exception as e:
            return {"response": None, "error": f"Unexpected error: {e}"}


class OpenAIChatSession:
    """
    A class to manage an OpenAI chat session with global instructions.
    """

    def __init__(self, args, api_key):
        self.model = args["model"]
        self.api_key = api_key

        cot_prompt = ""
        # test normal prompts
        #'''
        if args["format"] == "JSON":
            cot_prompt = COTPRMOPT["JSON"]
        elif args["format"] == "XML":
            cot_prompt = COTPRMOPT["XML"]
        elif args["format"] == "SQL":
            cot_prompt = COTPRMOPT["SQL"]
        elif args["format"] == "JavaScript":
            cot_prompt = COTPRMOPT["JavaScript"]
        
        # print("cot_prompt :", cot_prompt)
        self.messages = [
            {
                "role": "system",
                "content": cot_prompt
            }
        ]

        self.client = OpenAI(api_key=self.api_key)

    def _sanitize_unicode(self, text):
        """
        Remove invalid surrogate pairs from a Unicode string.
        """
        return re.sub(r'[\ud800-\udfff]', '', text)

    def add_message(self, role, content):
        """
        Add a message to the conversation history.

        Args:
            role (str): The role of the sender ('system', 'user', or 'assistant').
            content (str): The content of the message.
        """
        self.messages.append({"role": role, "content": content})

    def send_message(self, user_message):
        """
        Send a message to the OpenAI API and get a response.

        Args:
            user_message (str): The user's input message.

        Returns:
            dict: The AI's response and token usage.
        """
        sanitized_message = self._sanitize_unicode(user_message)
        self.add_message("user", sanitized_message)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages
            )

            assistant_message = response.choices[0].message.content if response.choices else None
            prompt_tokens = response.usage.prompt_tokens if response.usage else 0

            return {
                "response": assistant_message,
                "token_usage": prompt_tokens
            }

        except RateLimitError as e:
            print(f"Rate limit error encountered: {e}")
            print("Sleeping for 30 seconds to retry...")
            time.sleep(30)
            return {"response": None, "error": "Rate limit error"}

        except Exception as e:
            return {"response": None, "error": str(e)}


class OpenAIChatSessionForSeed:
    """
    A class to manage a chat session focused on seed generation for testing.
    """

    def __init__(self, args, api_key):
        self.model = args["model"]
        self.api_key = api_key
        format = args["format"]
        format_file_map = {
        "JavaScript": ".js",
        "SQL": ".sql",
        "JSON": ".json",
        "XML": ".xml"
        }

        seed_prompt = (
            f"You are a knowledgeable structural Seed Generator for test input of different formats, such as JSON/JavaScript/XML/SQL (the new test input should be from \".sql/.js/.json/.xml\" file). You are asked to generate new seeds before or during testing\
            During testing, given test input – coverage history map (consistently provided during testing, please remember these maps) and uncovered branches, please generate new seed step by step: \
            \
            1. Compare the covered and uncovered branches.\
                - Understand the meaning of the branch record. Each record is formatted as fileName_functionName_lineNumber_columnNumber_branchType_branchId. \
                 `branchType` can be `br` (i.e., `if`) or `switch`. The `branchId` is the case value in the switch branch and omitted in the if branch. \
                - Group by source location (fileName + funcName + lineName + columnName), and identify where alternative branches exist (e.g., case 37 was taken, case 42 not taken when type is `switch`, take the opposite branch if the type is `br`). \
            2. Analyze input string and infer which byte(s) most likely influenced the decision at relevant locations. \
                - Use the difference between branch IDs as clues to infer. \
                - Assume switch cases may correspond to input bytes or fields. \
            3. Randomly select one of the options to generate a new input based on the above analysis. \
                - Option 1: Generate new seed by modifying test inputs from history to explore uncovered branches. \
                - Option 2: Generate a fresh input from bug repository to explore uncovered features. \
                - If the given uncovered branches are empty, just use randomly generate a fresh input from bug repository with as many as features as possible.  \
            4. Ensure final output is enclosed with ```: Please just output the valid test input in ```...``` without any explanations or extra chars \
            Below are examples to guide you. \n" 
            "Q1: This is before testing. Please generate a high-quality JavaScript seed input (only JavaScript code usually stored with `.js` file) (sample code from existing bug repositories, e.g., for fuzzing, reproduction, or academic analysis, between 50 - 300 bytes) to start testing. \
             The goal is to help cover as much as code coverages and to detect new vulnerabilities.\
            \
            Think internally step by step: \
            1. Find sample from open source github or other bug repositories (e.g., for fuzzing, reproduction, or academic analysis): \
                - Seach the website like Mozilla Bugzilla/V8 issue tracker/WebKit bug tracker/GitHub security advisories or PoC datasets. \
                - There is a test case that led to a TypeError due to incorrect optimization behavior from V8 issue tracker. ```function main() {\
                    function f(v1, v2, v3) {\
                    const a = [1.1, 2.2, 3.3];\
                    const b = [4.4];\
                    const c = a.concat(b);\
                    c[10] = 5.5;\
                    return c.includes(v1, v2, v3);\
                }\
                for (let i = 0; i < 1e5; i++) {\
                 f(5.5, -0, \"unused\");\
                }\
                }\
            main();\
            ```\
            2. Omit the thinking procedures and only give the final answer. \
            \
            A1: \```function main() {\
            function f(v1, v2, v3) {\
            const a = [1.1, 2.2, 3.3];\
            const b = [4.4];\
            const c = a.concat(b);\
            c[10] = 5.5;\
            return c.includes(v1, v2, v3);\
            }\
            for (let i = 0; i < 1e5; i++) {\
                f(5.5, -0, \"unused\");\
            }\
            }\
        main();\
        ``` "
            "Q2: This is during running and the testing was saturated. Based on the coverage history (provided in previous converstaions), please generate a high-quality valid JavaScript test input (only JavaScript code) to cover the following untaken branches ```quickjs.c_next_token_19451_5_switch_88, \
        quickjs.c_next_token_19451_5_switch_89,quickjs.c_next_token_19451_5_switch_9,quickjs.c_next_token_19451_5_switch_90,quickjs.c_next_token_19451_5_switch_92,quickjs.c_next_token_19451_5_switch_94,quickjs.c_next_token_19451_5_switch_95,quickjs.c_next_token_19451_5_switch_96,quickjs.c_next_token_19451_5_switch_97,quickjs.c_next_token_19451_5_switch_98``` \
            Think internally step by step: \
            1. Compare the covered and uncovered branches: \
                - Assume the branch `quickjs.c_next_token_19451_5_switch_97` is taken from history. We now can know the uncovered branch `quickjs.c_next_token_19451_5_switch_88` can be the same group.\
                 We will use such information to infer dependence between input strings and uncovered branches \
            2. Analyze input string and infer which byte(s) most likely influenced the decision at relevant locations.\
                - From the swith branchID `97`, we cound infer the letter `a` is likely the key char to cover the branch. \
                - We need to think about the branch ID in the uncovered branch, which is 88, referring to `X` in char.\.\
            3. Randomly select one of the options to generate a new input based on above analysis.\
                - Randomly select Option 1 to generate a new seed input. \
                - Based on the test input that covers a similar branch `quickjs.c_next_token_19451_5_switch_97`, slightly modify the test input to make it possibly cover the uncovered branch `quickjs.c_next_token_19451_5_switch_89`. \                - For example, `SpeciesConstructor` means that some code should handle the constructor to cover the untaken branch. So, we can generate a code that contains constructors to increase the possibility of covering it.\
            4. Omit the thinking procedures and only give the final answer. \
            A2: (Assume the following is a modified test input from historical coverage map, DO NOT OUTPUT THIS)```function parseChar(c) {\
                switch (c) {\
                    case \"A\":\
                        return \"Matched A\";\
                    case \"X\":\
                        return \"Matched X\";\
                    case \"Z\":\
                        return \"Matched Z\";\
                default:\
                    return \"Unknown\";\
                }\
            }\
            const input = \"X\";\
            console.log(parseChar(input));"
             "Q3: This is during running and the testing was saturated. Based on the coverage history (provided in previous conversations), please generate a high-quality valid JavaScript test input (only JavaScript code) to cover the following untaken branches ```quickjs.c_next_token_19451_5_switch_88, \
        quickjs.c_next_token_19451_5_switch_89,quickjs.c_next_token_19451_5_switch_9,quickjs.c_next_token_19451_5_switch_90,quickjs.c_next_token_19451_5_switch_92,quickjs.c_next_token_19451_5_switch_94,quickjs.c_next_token_19451_5_switch_95,quickjs.c_next_token_19451_5_switch_96,quickjs.c_next_token_19451_5_switch_97,quickjs.c_next_token_19451_5_switch_98``` \
            Think internally step by step: \
            1. Compare the covered and uncovered branches: \
                - Assume the branch `quickjs.c_next_token_19451_5_switch_97` is taken from history. We now can know the uncovered branch `quickjs.c_next_token_19451_5_switch_88` can be the same group.\
                 We will use such information to infer dependence between input strings and uncovered branches \
            2. Analyze input string and infer which byte(s) most likely influenced the decision at relevant locations.\
                - From the swith branchID `97`, we cound infer the letter `a` is likely the key char to cover the branch. \
                - We need to think about the branch ID in the uncovered branch, which is 88, referring to `X` in char.\.\
            3. Randomly select one of the options to generate a new input based on above analysis.\
                - Randomly select Option 2 to generate a new seed input. \
                - Think about some new features byond the both covered or uncovered features. \
                - For example, the type errors might be interesting features unexplored. \
                - Generate a fresh test input from the bug repository to cover the interesting but unexplored features.\
            4. Omit the thinking procedures and only give the final answer. \
            A3: (Assume the following is a fresh test input from bug repository that can explore new features, DO NOT OUTPUT THIS)```function parseChar(c) {\
                switch (c) {\
                    case \"A\":\
                        return \"Matched A\";\
                    case \"X\":\
                        return \"Matched X\";\
                    case \"Z\":\
                        return \"Matched Z\";\
                default:\
                    return \"Unknown\";\
                }\
            }\
            const input = \"X\";\
            console.log(parseChar(input));"
        )
        # print("seed_prompts : ", seed_prompt)
        self.messages = [
            {
                "role": "system",
                "content": seed_prompt
            }
        ]

        self.client = OpenAI(api_key=self.api_key)

    def _sanitize_unicode(self, text):
        """
        Remove invalid surrogate pairs from a Unicode string.
        """
        return re.sub(r'[\ud800-\udfff]', '', text)

    def add_message(self, role, content):
        """
        Add a message to the conversation history.

        Args:
            role (str): The role of the sender ('system', 'user', or 'assistant').
            content (str): The content of the message.
        """
        self.messages.append({"role": role, "content": content})

    def send_message(self, user_message):
        """
        Send a message to the OpenAI API and get a response.

        Args:
            user_message (str): The user's input message.

        Returns:
            dict: The AI's response and token usage.
        """
        sanitized_message = self._sanitize_unicode(user_message)
        self.add_message("user", sanitized_message)

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages
            )

            assistant_message = response.choices[0].message.content if response.choices else None
            prompt_tokens = response.usage.prompt_tokens if response.usage else 0

            return {
                "response": assistant_message,
                "token_usage": prompt_tokens
            }

        except RateLimitError as e:
            print(f"Rate limit error encountered: {e}")
            print("Sleeping for 30 seconds to retry...")
            time.sleep(30)
            return {"response": None, "error": "Rate limit error"}

        except Exception as e:
            return {"response": None, "error": str(e)}


def safe_print(text):
    """
    Safely print text by removing invalid surrogate characters.
    """
    safe_text = ''.join(c for c in text if not (0xD800 <= ord(c) <= 0xDFFF))
    print(safe_text)


def normalize_string(input_string: str) -> str:
    """
    Normalize a string by decoding escape sequences and ensuring consistent formatting.
    Handles invalid escape sequences gracefully.
    """
    import codecs

    try:
        # Replace invalid escape sequences (like \x) with their raw representation
        input_string = codecs.decode(input_string, 'unicode_escape')
    except UnicodeDecodeError as e:
        print(f"Error decoding escape sequences: {e}")
        # Handle invalid escape sequences by escaping backslashes
        input_string = input_string.encode('utf-8').decode('unicode_escape', errors='backslashreplace')
    return input_string


def read_last_line(file_path):
    """
    Reads the last line of a file, removes the part after the last ')' character,
    and returns the modified string.

    :param file_path: Path to the file (str or Path object).
    :return: The modified last line of the file as a string, or an empty string if the file is empty.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                return ""
            last_line = lines[-1].strip()
            # Find the last ')' and return the string before it
            last_paren_index = last_line.rfind(')')
            return last_line[:last_paren_index + 1] if last_paren_index != -1 else last_line
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return ""
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return ""


def clean_and_prepare(paths):
    """
    Remove specified files, clean folder contents, and recreate specified folders.

    Args:
        paths (dict): A dictionary with keys:
            - "files": List of file paths to remove.
            - "folders": List of folders to remove completely and recreate.
            - "clean_folders": List of folders to clean (remove all contents but keep the folder).
    
    Returns:
        None
    """
    # Remove specified files
    for file_path in paths.get("files", []):
        if os.path.exists(file_path):
            os.remove(file_path)
            print(f"Removed file: {file_path}")

    # Remove and recreate specified folders
    for folder_path in paths.get("folders", []):
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)
        os.makedirs(folder_path)
        print(f"Recreated folder: {folder_path}")

    # Clean specified folders (remove contents but keep the folder)
    for folder_path in paths.get("clean_folders", []):
        if os.path.exists(folder_path) and os.path.isdir(folder_path):
            for item in os.listdir(folder_path):
                item_path = os.path.join(folder_path, item)
                if os.path.isfile(item_path) or os.path.islink(item_path):
                    os.unlink(item_path)
                elif os.path.isdir(item_path):
                    shutil.rmtree(item_path)
            print(f"Cleaned folder contents: {folder_path}")


def main():

    paths_to_clean = {
    "files": [
        "global-tree.json",
        "run_cottontail_log.txt",
        "path-constraints-expr.json",
        "gpt-results-openai.txt",
        "input-bytes.json"
    ],
    "folders": [
        "output" # Equivalent to `rm -rf output ; mkdir output`
    ],
    "clean_folders": [
        "gpt-output",
        "gpt-output-raw",
        "z3-output"
        # Uncomment if you want to clear "input" and "symcc-output"
        # "input",
        # "symcc-output"
    ]
    }

    clean_and_prepare(paths_to_clean)
    args = dict()
    run = sys.argv[0]
    cfg = ConfigParser()
    cfg.read('./config.ini'.format(run))

    args["gcov_dir"] =Path(cfg.get('gcov-locations', 'gcovDir')).resolve()
    args["source_dir"] = Path(cfg.get('gcov-locations', 'sourceDir')).resolve()
  
    args["in_dir"] = Path(cfg.get('running-locations', 'inputDir')).resolve()
    args["out_dir"] = Path(cfg.get('running-locations', 'outputDir')).resolve()
    args["failed_dir"] = Path(cfg.get('running-locations', 'failedDir')).resolve()

    args["cottontail_target"] = cfg.get('running-targets', 'cottontailTarget') + " @@"
    raw_target = args["cottontail_target"]
    args["gcov_target"] = cfg.get('running-targets', 'gcovTarget') + " @@"
    test_target = args["gcov_target"]
    args["record_file"] = cfg.get('gcov-locations', 'recordFile')
    args["format"] = cfg.get('common-settings', 'format')

    args["model"] = cfg.get('common-settings', 'gpt_model')
    
    args["timeout"] = cfg.getfloat('running-params', 'timeout')
    args["cov_timeout"] = cfg.getfloat('running-params', 'cov_timeout')
    args["saturation_timeout"] = cfg.getfloat('running-params', 'saturation_timeout')

    # Create a temp work environment
    work_dir = Path(tempfile.mkdtemp())
    (work_dir / "next").mkdir(parents=True, exist_ok=True)
    (work_dir / "symcc_out").mkdir(parents=True, exist_ok=True)
    (work_dir / "analyzed_inputs").touch(exist_ok=True)

    # Possibly create out/failed_dir
    out_dir = args["out_dir"]
    in_dir = args["in_dir"]
    failed_dir = args["failed_dir"]
    if out_dir:
        out_dir.mkdir(parents=True, exist_ok=True)
    if failed_dir:
        failed_dir.mkdir(parents=True, exist_ok=True)

    def cleanup():
        """
        Cleans up the work directory, replicating `trap cleanup EXIT`.
        """
        if work_dir.exists():
            shutil.rmtree(work_dir, ignore_errors=True)

    # We replicate some environment variables from the script
    os.environ["SYMCC_OUTPUT_DIR"] = str(work_dir / "symcc_out")
    os.environ["SYMCC_ENABLE_LINEARIZATION"] = "1"
    os.environ["SYMCC_AFL_COVERAGE_MAP"] = str(work_dir / "map")

    # Timers and counters
    gen_count = 0
    cov_timeout = args["cov_timeout"]
    saturation_timeout = args["saturation_timeout"]
    running_timeout =  args["timeout"]
    last_execution = time.time()
    llast_execution = time.time()
    gpt_last_execution = time.time()
    
    untaken_branches = {}

    if args["source_dir"]:
        build_dir_path = args["source_dir"]
        # Construct the find command dynamically
        subprocess.run(
        [
            "find",
            build_dir_path,
            "-type",
            "f",
            "-name",
            "*.gcda",
            "-exec",
            "rm",
            "-f",
            "{}",
            "+",
        ],
        check=True,
        )
        print(f"Removed *.gcda files in: {build_dir_path}")
   
    # The script also removes a file named all_records.txt
    if args["record_file"]:
        ar_txt = Path(cfg.get('gcov-locations', 'recordFile')).resolve()
        print(f"Constructed path: {ar_txt}")
    else:
        raise ValueError(f"Program '{program}' is not in TARGDIR mapping!")
    if ar_txt.exists():
        ar_txt.unlink()

    # Some environment toggles
    os.environ["USE_ESCT"] = cfg.get('running-params', 'use_esct')
    os.environ["USE_GPT_SOLVING"] = cfg.get('running-params', 'use_gpt_solving')
    os.environ["USE_NO_MAP"] = cfg.get('running-params', 'use_no_map')

    os.environ["ALPHA"] = cfg.get('running-params', 'ALPHA')
    os.environ["BETA"]  = cfg.get('running-params', 'BETA')
    os.environ["GAMMA"] = cfg.get('running-params', 'GAMMA')
    os.environ["THRESHOLD"] = cfg.get('running-params', 'THRESHOLD')

    use_gpt_seed_generation = cfg.getfloat('running-params', 'use_gpt_seed_generation')
    use_gpt_history_update = cfg.getfloat('running-params', 'use_gpt_history_update')
    use_gpt_validator = cfg.getfloat('running-params', 'use_gpt_validator')

    # Add some statistic numbers
    gpt_invocation_cnt = 0
    gpt_sovling_time = 0
    gpt_seed_generation_cnt = 0
    gpt_history_update_cnt = 0
    total_pc_cnt = 0
    gpt_generated_testcases_cnt = 0
    gpt_missed_testcases_cnt = 0
    valid_testcases_cnt = 0
    invalid_testcases_cnt = 0
    prompt_token_cnt = 0

    is_not_interesting_cnt = 0
    no_increasing_cov_cnt = 0

    g_total_pc = 0

    use_gpt_flag = os.environ.get("USE_GPT_SOLVING", "0")
    
    # Init the GPT chatting session (once per run)
    # Initialize OpenAI client
    if use_gpt_flag == '1':
        api_key = cfg.get('common-settings', 'api_key')
        if is_folder_empty("input"):
            print("Input Folder is empty; generate a input to start testing ...")
            gpt_seed_generation_cnt += 1

            format = args["format"]
            user_input = f"Please generate a high-quality {format} seed input (only {format} strings) ( sample code from existing bug repositories, e.g., for fuzzing, reproduction, or academic analysis, between 50 - 300 bytes) to start testing. The goal is to help cover as much as code coverages and to detect new vulnerabilities."
            if "gpt" in args["model"]:
                chat_session_for_seed = OpenAIChatSessionForSeed(args, api_key)
            elif "deepseek" in args["model"]:
                chat_session_for_seed = DeepSeekChatSessionForSeed(args, api_key)
            response = chat_session_for_seed.send_message(user_input)
            print("User input for seed generation: ", user_input)
            print("Response for seed generation: ", response)
            if (response["response"] != ""):
                save_cleaned_content_to_file("input", response["response"])
    '''       
    if use_gpt_seed_generation == '1':
        if "gpt" in args["model"]:
            chat_session_for_seed = OpenAIChatSessionForSeed(args, api_key)
        elif "deepseek" in args["model"]:
            chat_session_for_seed = DeepSeekChatSessionForSeed(args, api_key)
    '''
    try:
        while True:
            gpt_failed_cnt = 0
            all_current_time = time.time()
            all_elapsed = all_current_time - llast_execution
            if all_elapsed >= running_timeout:
                report_coverage(args)
                print("Timeout is reached, stop the running now...")
                update_running_log("run_cottontail_log.txt", str(fpath), args, all_elapsed, gpt_invocation_cnt, gpt_solving_time, gpt_seed_generation_cnt,
                    gpt_history_update_cnt, total_pc_cnt, gpt_generated_testcases_cnt, gpt_missed_testcases_cnt, valid_testcases_cnt,
                    invalid_testcases_cnt, is_not_interesting_cnt, prompt_token_cnt)
                last_coverage = read_last_line(args["record_file"])
                print("Last coverage : ", last_coverage)
                exit(1)

            # Step 1: maybe_import from external input directory
            if gen_count == 0:
                maybe_import(in_dir, work_dir)
                cur_dir = work_dir / "cur"
                if cur_dir.exists():
                    shutil.rmtree(cur_dir)
    
            # Step 2: move next -> cur
            cur_dir = work_dir / "cur"
            
            (work_dir / "next").rename(cur_dir)
            (work_dir / "next").mkdir(parents=True, exist_ok=True)

            # Step 3: If cur is empty, exit
            if not any(cur_dir.iterdir()):
                print("Waiting for more input...")
                if use_gpt_seed_generation == 1:
                    # cur_dir.rmdir()
                    # seed generation with the help of map
                    gpt_seed_generation_cnt += 1
                    format = args["format"]
                    # untaken_nodes = find_untaken_nodes("global-tree.json")
                    user_input_seed_generation = ""
                    if use_gpt_history_update == 1 and all_elapsed > 10:
                        # untaken_branches = find_untaken_nodes("global-tree.json")
                        find_untaken_nodes("global-tree.json", untaken_branches)
                        user_input_seed_generation = f"This is during running and the testing was saturated. Based on the coverage history (provided in previous converstaions), and following untaken branches ```" + ",".join(map(str, untaken_branches.keys())) + f"```, please generate a high-quality valid {format} seed input based on the system prompts"
                    else:
                        user_input_seed_generation = f"This is during running and the testing was saturated. Please generate a high-quality valid {format} seed input to re-start testing"
                    print("user_input_seed_generation : ", user_input_seed_generation)
                    response = chat_session_for_seed.send_message(user_input_seed_generation)
                   
                    if (response["response"] != ""):
                        save_cleaned_content_to_file(cur_dir, response["response"])
                         # save the seed to input
                        store_test_cases_with_count(cur_dir / "seed", "input", gpt_seed_generation_cnt)
                    else:
                        print("Get a null response, create again")
                        continue

                else:
                    print("Just exit...")
                    cur_dir.rmdir()
                    sys.exit(1)

            print(f"++++++++++++Generation {gen_count} ++++++++++++")
            global_last_coverage = ""
            if gpt_invocation_cnt != 0:
                global_last_coverage = read_last_line(args["record_file"])
            for fpath in list(cur_dir.iterdir()):
                #if not fpath.is_file():
                if os.path.isfile(fpath) and os.path.getsize(fpath) == 0:
                    print("Empty file; try again")
                    continue
                print(f"Running on {fpath}")
                current_time = time.time()
                elapsed = current_time - last_execution
                saturation_last_execution = 0

                # Check if our target has the literal ' @@ '
                # We'll replicate by checking if ' @@' in the string
                if " @@" in raw_target:
                    # Symbolic run
                    if use_gpt_flag == '0':
                        #print("Normal Z3 running\n")
                        target_cmd = raw_target.replace("@@", str(fpath))
                        env = {"SYMCC_INPUT_FILE": str(fpath)}
                        ret_code, _ = run_command(
                            ["bash", "-c", target_cmd],
                            timeout_sec=90,
                            extra_env=env,
                        )
                        # TODO solve constraints here

                        json_path = "path-constraints-expr.json"
                        name_mapping = simplify_keys_in_json_with_mapping(json_path)
                        pc_dict = load_json_to_dict(json_path)
                        total_pc_cnt = len(pc_dict)
                        g_total_pc += total_pc_cnt
                        # print("total_pc_cnt = ", total_pc_cnt)
                        
                        # solve the constraint one by one
                        for name in name_mapping:
                            if len(pc_dict[name]) > 300: # skipp too complex constraints or unsat constraints
                                print("Too complex constraint, skip ...")
                                continue

                            raw_constraint = pc_dict[name]
                            smt2_constraint = smtlibify(raw_constraint)
                            parsed_exprs = z3.parse_smt2_string(smt2_constraint)
                            pre_expr = get_first_assert_expr(parsed_exprs)
                            is_sat = checkFeasiblity (pre_expr)
                            if is_sat is not True: # skipp too complex constraints or unsat constraints
                                print("UNSAT constraint, skip ...")
                                continue
                            my_expr = get_first_assert_expr(parsed_exprs)
                            sol_list = getSolutionAll(my_expr)
                            modified_input = replace_bytes_with_holes_and_truncate_from_json(pc_dict[name], "input-bytes.json")
                            refined_string = refine_string(sol_list, modified_input, "input-bytes.json")
                            save_string_to_file("gpt-results-openai.txt", refined_string)
                            store_test_cases_with_count("gpt-results-openai.txt", work_dir / "symcc_out", gpt_generated_testcases_cnt)
                            store_test_cases_with_count("gpt-results-openai.txt", "z3-output", gpt_generated_testcases_cnt)
    
                           #  print("End running natively ... ")
                            test_cmd_str = test_target.replace("@@", str(f"gpt-output/{gpt_generated_testcases_cnt}"))
                            ret_code2, has_error2 = run_command(
                            ["bash", "-c", test_cmd_str],
                            timeout_sec=90,)
                            save_failed(ret_code2, fpath, failed_dir, has_error2)
                            # print("End running natively ... ")
                            gpt_generated_testcases_cnt += 1
                            #g_total_pc += 1
                        # exit(1)

                    else:
                        print("GPT solving running\n")
                        print("Now concolic executing ", fpath)
                        print("Content:\n ", str(fpath))
                        if "gpt" in args["model"]:
                            print("model : ", args["model"])
                            chat_session = OpenAIChatSession(args, api_key)
                        elif "deepseek" in args["model"]:
                            print("model : ", args["model"])
                            chat_session = DeepSeekChatSession(args, api_key)

                        target_cmd = raw_target.replace("@@", str(fpath))
                        env = {"SYMCC_INPUT_FILE": str(fpath)}
                        ret_code, _ = run_command(
                            ["bash", "-c", target_cmd],
                            timeout_sec=90,
                            extra_env=env,
                        )
                        #exit(1)
                        # TODO
                        # Step1: collect path constraints
                        pc_file = Path("path-constraints-expr.json")
                        if not pc_file.is_file(): # file not exists
                            print("path-constraints-expr.json is not generated ... why?")
                            os.system("rm input-bytes.json; rm input-bytes-after-solving.json")
                            # break
                            continue
                       
                        json_path = "path-constraints-expr.json"
                        os.system("cp path-constraints-expr.json path-constraints-expr-old.json")
                        name_mapping = simplify_keys_in_json_with_mapping(json_path)

                        pc_dict = load_json_to_dict(json_path)
                        total_pc_cnt = len(pc_dict)
                        g_total_pc += total_pc_cnt
                        print("total_pc_cnt = ", total_pc_cnt)

                        # solve the constraint one by one
                        for name in name_mapping:
                            gpt_current_time = time.time()
                            gpt_elapsed = gpt_current_time - gpt_last_execution
                            saturation_elapsed = gpt_current_time - saturation_last_execution
                            #print("Now GPT sovling branch ", name)
                            elapsed = current_time - last_execution
                            # Step 2: solve the path constraints using GPT
                            modified_input = replace_bytes_with_holes_and_truncate_from_json(pc_dict[name], "input-bytes.json")
                            if modified_input == "":
                                continue
                            #print("Len of constraints : ", len(pc_dict[name]))
                            if len(pc_dict[name]) > 300: # skipp too complex constraints or unsat constraints
                                print("Too complex constraint, skip ...")
                                continue

                            raw_constraint = pc_dict[name]
                            smt2_constraint = smtlibify(raw_constraint)
                            parsed_exprs = z3.parse_smt2_string(smt2_constraint)
                            pre_expr = get_first_assert_expr(parsed_exprs)
                            is_sat = checkFeasiblity (pre_expr)
                            #print("Is the constraint solveable? : ", is_sat)
                            if is_sat is not True: # skipp too complex constraints or unsat constraints
                                print("UNSAT constraint, skip ...")
                                continue

                            user_input = "Here is the path constraint ```" + pc_dict[name] + "```, here is the test input you need to change ```" + modified_input + "```\n"
                            # print("User_input:")
                            # safe_print(user_input)

                            # Add the user's message to the conversation
                            # Call the OpenAI ChatCompletion endpoint with the entire conversation so far
                            gpt_start_time = time.time()
                            #time.sleep(5)
                            response_data = chat_session.send_message(user_input)
                            gpt_invocation_cnt += 1
                            gpt_end_time = time.time()
                            gpt_solving_time = gpt_end_time - gpt_start_time
                            # g_total_pc += 1
                            # Print it out
                            if response_data["response"] == None:
                            # if 0:
                                print("Stop for this stage because GPT does not give any response")
                                gpt_failed_cnt += 1
                                time.sleep(30)
                                if gpt_failed_cnt >= 100:
                                    exit(1)
                                break
                            # print("Response:")
                            # safe_print(response_data["response"])

                            # count token usage
                            token_usage = response_data["token_usage"]
                            # print(f"Token Usage: {token_usage}")
                            prompt_token_cnt += token_usage

                            save_string_to_file("gpt-results-openai.txt", response_data["response"])
                            
                            # Step 3: store the solutions to the corresponding folder (may add evaluator here)
                            if use_gpt_validator == 1:
                                #print("Store using validator\n")
                                raw_constraint = pc_dict[name]
                                testcase = read_file_content("gpt-results-openai.txt")
                                input_bytes = string_to_input_bytes(response_data["response"])
                            
                                smt2_constraint = smtlibify(raw_constraint)
                                parsed_exprs = z3.parse_smt2_string(smt2_constraint)
                                my_expr = get_first_assert_expr(parsed_exprs)
                                # print("my_expr : ", my_expr)
                                sat = evaluateSymbolicExpression(my_expr, input_bytes)
                                #print("SAT = ", sat)
                                
                                if sat == True: # check gpt_string satisfy the constraints
                                    valid_testcases_cnt += 1
                                    store_test_cases_with_count("gpt-results-openai.txt", work_dir / "symcc_out", gpt_generated_testcases_cnt)
                                    store_test_cases_with_count("gpt-results-openai.txt", "gpt-output", gpt_generated_testcases_cnt)

                                    # print("Start running natively ... ")
                                    test_cmd_str = test_target.replace("@@", str(f"gpt-output/{gpt_generated_testcases_cnt}"))
                                    # save the raw results from LLM
                                    # store_test_cases_with_count("gpt-results-openai.txt", "gpt-output-raw", gpt_generated_testcases_cnt)
                                    ret_code2, has_error2 = run_command(
                                    ["bash", "-c", test_cmd_str],
                                    timeout_sec=90,)
                                    save_failed(ret_code2, fpath, failed_dir, has_error2)
                                    # print("End running natively ... ")

                                else:
                                    invalid_testcases_cnt += 1
                                    sol_list = getSolutionAll(my_expr) # TODO need to test

                                    refined_string = refine_string(sol_list, modified_input, "input-bytes.json")
                                    save_string_to_file("gpt-results-openai.txt", refined_string)

                                    store_test_cases_with_count("gpt-results-openai.txt", work_dir / "symcc_out", gpt_generated_testcases_cnt)
                                    store_test_cases_with_count("gpt-results-openai.txt", "gpt-output", gpt_generated_testcases_cnt)

                                    test_cmd_str = test_target.replace("@@", str(f"gpt-output/{gpt_generated_testcases_cnt}"))
                                    ret_code2, has_error2 = run_command(
                                    ["bash", "-c", test_cmd_str],
                                    timeout_sec=90,)
                                    save_failed(ret_code2, fpath, failed_dir, has_error2)
                                    # print("End running natively ... ")

                                # print("name_mapping.get : ", name_mapping.get(name))
                                clean_name = re.sub(r"-d\d+$", "", str(name_mapping.get(name)))
                                is_interesting = mark_node_in_tree(clean_name, "global-tree.json")
                                # is_interesting = True
                                if is_interesting == True:
                                    is_not_interesting_cnt = 0;
                                else:
                                    is_not_interesting_cnt += 1

                            else:
                                print("Store without validator\n")
                                # gpt_file = store_test_cases("gpt-results-openai.txt", work_dir / "symcc_out")
                                store_test_cases_with_count("gpt-results-openai.txt", "gpt-output", gpt_generated_testcases_cnt)
                                
                                #print("Start running natively ... ")
                                test_cmd_str = test_target.replace("@@", str(f"gpt-output/{gpt_generated_testcases_cnt}"))
                                ret_code2, has_error2 = run_command(
                                ["bash", "-c", test_cmd_str],
                                timeout_sec=90,)
                                save_failed(ret_code2, fpath, failed_dir, has_error2)
                                # print("End running natively ... ")


                                # print("name_mapping.get : ", name_mapping.get(name))
                                clean_name = re.sub(r"-d\d+$", "", str(name_mapping.get(name)))
                                is_interesting = mark_node_in_tree(clean_name, "global-tree.json")
                                #is_interesting = True
                                if is_interesting == True:
                                    is_not_interesting_cnt = 0;
                                else:
                                    is_not_interesting_cnt += 1

                                valid_testcases_cnt += 1

                            gpt_generated_testcases_cnt += 1
                        
                            os.system("rm gpt-results-openai.txt")

                            update_running_log("run_cottontail_log.txt", str(fpath), args, all_elapsed, gpt_invocation_cnt, gpt_solving_time, gpt_seed_generation_cnt,
                            gpt_history_update_cnt, total_pc_cnt, gpt_generated_testcases_cnt, gpt_missed_testcases_cnt, valid_testcases_cnt,
                            invalid_testcases_cnt, is_not_interesting_cnt, prompt_token_cnt)

                            record = {
                                "gpt_invocation_cnt": str(gpt_invocation_cnt),
                                "gpt_solving_time": str(gpt_solving_time),
                                "gpt_seed_generation_cnt": str(gpt_seed_generation_cnt),
                                "gpt_history_update_cnt": str(gpt_history_update_cnt),
                                "total_pc_cnt": str(total_pc_cnt),
                                "gpt_generated_testcases_cnt": str(gpt_generated_testcases_cnt),
                                "gpt_missed_testcases_cnt": str(gpt_missed_testcases_cnt),
                                "valid_solving_cnt": str(valid_testcases_cnt),
                                "invalid_solving_cnt": str(invalid_testcases_cnt),
                                "is_not_interesting_cnt": str(is_not_interesting_cnt),
                                "prompt_token_cnt": str(prompt_token_cnt),
                            }
                            # print("LOG: ", record)
                            all_current_time = time.time()
                            all_elapsed = all_current_time - llast_execution
                            
                            # Possibly do coverage
                            
                            last_coverage = ""
                            if gpt_elapsed >= cov_timeout:
                                global_last_coverage = read_last_line(args["record_file"])
                                report_coverage(args)
                                gpt_last_execution = time.time()

                                last_coverage = read_last_line(args["record_file"])
                                print("Last coverage : ", last_coverage)
                                print("Previous coverage : ", global_last_coverage)

                                if str(global_last_coverage) == str(last_coverage) and global_last_coverage != "":
                                    no_increasing_cov_cnt += 1;
                                    print("Inrease the count for uninteresting : no_increasing_cov_cnt =  ", no_increasing_cov_cnt)
                                else:
                                    no_increasing_cov_cnt = 0
                                

                            # skip some uninteresting cases
                            if no_increasing_cov_cnt > saturation_timeout and use_gpt_seed_generation == 1:
                                # no_increasing_cov_cnt = 0
                                if gen_count > 0:
                                    print("Not a interesting case, skip this seed... ")
                                    # if no_increasing_cov_cnt > saturation_timeout and use_gpt_seed_generation == 1:
                                    # prev_gpt_seed_generation_cnt = gpt_seed_generation_cnt
                                    break
                                
                            if all_elapsed >= running_timeout:
                                report_coverage(args)
                                print("Timeout is reached, stop the running now...")
                                if use_gpt_flag == '1':
                                    update_running_log("run_cottontail_log.txt", str(fpath), args, all_elapsed, gpt_invocation_cnt, gpt_solving_time, gpt_seed_generation_cnt,
                                        gpt_history_update_cnt, total_pc_cnt, gpt_generated_testcases_cnt, gpt_missed_testcases_cnt, valid_testcases_cnt,
                                        invalid_testcases_cnt, is_not_interesting_cnt, prompt_token_cnt)
                                last_coverage = read_last_line(args["record_file"])
                                print("Last coverage : ", last_coverage)
                                exit(1)

                            #print("--- gen_count = ", gen_count)
                        
                        os.system("rm path-constraints-expr.json; rm input-bytes.json")
        
                else:
                    # Concrete run
                    # $timeout $target $f ...
                    # Let's replicate
                    target_cmd = [raw_target, str(fpath)]
                    # raw_target may have spaces; let's keep it simple and assume no
                    ret_code, _ = run_command(
                        ["bash", "-c", " ".join(target_cmd)],
                        timeout_sec=90
                    )
                    if ret_code == 134 and failed_dir:
                        # Just save the file
                        save_failed(1, fpath, failed_dir, has_error=False)

                # Now run test_target on the newly generated files in symcc_out
                if use_gpt_flag == '1' and use_gpt_history_update == 1:
                    # TODO update history coverage
                    print("Start to update history information")
                    last_global_tree = Path("global-tree-last.json")
                    if last_global_tree.is_file():
                        newly_taken_nodes = find_newly_taken_nodes("global-tree.json", "global-tree-last.json")
                        print("Newly taken nodes:", newly_taken_nodes)
                        if len(newly_taken_nodes) != 0:
                            os.system("cp global-tree.json global-tree-last.json")
                            user_input_history = "This is during testing. Please remember the following mapping information. The test case ```" + read_file_content(fpath) + " covers the following branches ```" + ",".join(map(str, newly_taken_nodes)) + "```"
                            if "gpt" in args["model"]:
                                chat_session_for_seed = OpenAIChatSessionForSeed(args, api_key)
                            elif "deepseek" in args["model"]:
                                chat_session_for_seed = DeepSeekChatSessionForSeed(args, api_key)
                            chat_session_for_seed.add_message("user", user_input_history) # no need to update everytime, just maintain a list.
                            gpt_history_update_cnt += 1
                        
                # print("Start running natively ... ")
                test_cmd_str = test_target.replace("@@", str(fpath))
                # Then run it, capturing output or logging as you wish:
                ret_code2, has_error2 = run_command(
                ["bash", "-c", test_cmd_str],
                timeout_sec=90,)
                save_failed(ret_code2, fpath, failed_dir, has_error2)
                #print("End of running natively ...")
    
                symcc_out_dir = work_dir / "symcc_out"

                if no_increasing_cov_cnt > saturation_timeout and use_gpt_seed_generation == 1:
                    print("Start generate new inputs as testing process was saturated ...")
                    if gen_count > 0:
                        clear_folder(cur_dir)
                        # Clean up the cur input
                        clear_folder(work_dir / "symcc_out")
                        clear_folder(work_dir / "next")
                        gen_count = 0
                        # break
                    no_increasing_cov_cnt = 0
                
                # Add newly generated testcases to next
                add_dir = work_dir / "next"
                copy_with_unique_name(symcc_out_dir, add_dir)

                # Possibly export
                if out_dir:
                    maybe_export(symcc_out_dir, out_dir)

                # remove already analyzed from next
                remove_analyzed(work_dir, add_dir)
               
                # Mark fpath as analyzed
                with (work_dir / "analyzed_inputs").open("a") as af:
                    af.write(f"{fpath.name}\n")

                # Clean up the cur input
                if fpath.exists():
                    fpath.unlink()

                # Possibly do coverage
                if elapsed >= cov_timeout:
                    report_coverage(args)
                    last_execution = time.time()

                all_current_time = time.time()
                all_elapsed = all_current_time - llast_execution
                if all_elapsed >= running_timeout:
                    report_coverage(args)
                    print("Timeout is reached, stop the running now...")
                    if use_gpt_flag == '1':
                        update_running_log("run_cottontail_log.txt", str(fpath), args, all_elapsed, gpt_invocation_cnt, gpt_solving_time, gpt_seed_generation_cnt,
                            gpt_history_update_cnt, total_pc_cnt, gpt_generated_testcases_cnt, gpt_missed_testcases_cnt, valid_testcases_cnt,
                            invalid_testcases_cnt, is_not_interesting_cnt, prompt_token_cnt)
                    last_coverage = read_last_line(args["record_file"])
                    exit(1)

            gen_count += 1
            os.system("cp global-tree.json global-tree-last.json")
            
            # Cleanup the cur directory
            if cur_dir.exists():
                shutil.rmtree(cur_dir)

            if gen_count == 1:
                print("First iteration is done, exit")
                report_coverage(args)
                last_coverage = read_last_line(args["record_file"])

            # Another coverage check outside the for-loop
            # (in case there's no next iteration)
            current_time = time.time()
            elapsed = current_time - last_execution
            if elapsed >= cov_timeout:
                report_coverage(args)
                last_execution = time.time()
    finally:
        cleanup()

if __name__ == "__main__":
    main()
