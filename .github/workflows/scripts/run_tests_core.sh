#!/bin/sh
set -e

# C++
bazel test --test_output=all //pir/cpp/...
