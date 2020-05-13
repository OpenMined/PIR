# Private Information Retrieval

## Requirements

There are requirements for the entire project which each language shares. There also could be requirements for each target language:

### Global Requirements

These are the common requirements across all target languages of this project.

- A compiler such as clang, gcc, or msvc
- [Bazel](https://bazel.build)

## Compiling and Running

The repository uses a folder structure to isolate the supported targets from one another:

```
pir/<target language>/<sources>
```

### C++

See the [C++ README.md](pir/cpp/README.md)

## Using the Library

To use this library in another Bazel project, add the following in your WORKSPACE file:

```
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

git_repository(
   name = "org_openmined_pir",
   remote = "https://github.com/OpenMined/PIR",
   branch = "master",
   init_submodules = True,
)

load("@org_openmined_pir//pir:preload.bzl", "pir_preload")

pir_preload()

load("@org_openmined_pir//pir:deps.bzl", "pir_deps")

pir_deps()

```
