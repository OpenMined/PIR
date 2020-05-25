#!/bin/sh
set -e

# C++
bazel build --copt="-Werror" //pir/cpp/...
