# PIR - C++

## Build and test


Build all libraries with or without optimizations, or build a specific module

```
# Build everything using the fastbuild optimization configuration
bazel build //pir/cpp/...

# With a specific optimization flag '-c opt'
bazel build -c opt //pir/cpp/...

```

Build and run tests

```
bazel test //pir/cpp/...
```

Build and run benchmarks

```
bazel run -c opt //pir/cpp:benchmark
```
