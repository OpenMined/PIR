# PIR - C++

## Build and test


Build all libraries with or without optimizations, or build a specific module

```
# Build everything using the fastbuild optimization configuration
bazel build --cxxopt='-std=c++17' //pir/cpp/...

# With a specific optimization flag '-c opt'
bazel build -c opt --cxxopt='-std=c++17' //pir/cpp/...

```

Build and run tests

```
bazel test --cxxopt='-std=c++17' //pir/cpp/...
```
