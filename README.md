![om-logo](https://github.com/OpenMined/design-assets/blob/master/logos/OM/horizontal-primary-trans.png)

[![Tests](https://github.com/OpenMined/PSI/workflows/Tests/badge.svg?branch=master&event=push)](https://github.com/OpenMined/PSI/actions?query=workflow%3ATests+branch%3Amaster+event%3Apush)
![License](https://img.shields.io/github/license/OpenMined/PIR)
![OpenCollective](https://img.shields.io/opencollective/all/openmined)


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

## Usage

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

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## Contributors

See [CONTRIBUTORS.md](CONTRIBUTORS.md).

## License
[Apache License 2.0](https://choosealicense.com/licenses/apache-2.0/)
