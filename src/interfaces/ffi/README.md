Files under this module allow exposing a C ABI interface for integration to Python, Java, C, C++ etc...


For the generated dynamic library to expose the external functions, the library must be built with the ` --features ffi` flag i.e.

```bash
cargo b --release --features ffi
```
