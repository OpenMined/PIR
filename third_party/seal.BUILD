load("@rules_foreign_cc//tools/build_defs:cmake.bzl", "cmake_external")

filegroup(
    name = "src", 
    srcs = glob(["**"]), 
    visibility = ["//visibility:public"]
)

cmake_external(
   name = "seal",
   cmake_options = [
        "-DSEAL_USE_MSGSL=OFF",
        "-DSEAL_USE_ZLIB=OFF",
        "-DCMAKE_CXX_STANDARD=17",
   ],
   cache_entries = {
        "MAKE_INSTALL_PREFIX": "$EXT_BUILD_DEPS/seal",
        "SEAL_LIB_BUILD_TYPE": "Static_PIC",
   },
   lib_source = ":src",
   install_prefix = "native/src",
   out_include_dir = "include/SEAL-3.5",
   static_libraries = ["libseal-3.5.a"],
   visibility = ["//visibility:public"],
)
