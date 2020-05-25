#!/bin/sh
set -e

# C++
bazel test --test_output=all --copt="-Werror" //pir/cpp/...
