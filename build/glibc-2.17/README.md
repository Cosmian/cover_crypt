This docker directory provides

 - a Dockerfile to build a docker image appropriate to build this library against GLIBC2.17
 - a build script to build this library using the docker image


### Build the docker image

In this directory, run

```bash
sudo docker build . -t rust_2.17
```

### Build the library

In this directory, run

```bash
./build.sh
```

The artifacts for GLIBC2.17 will be located in `PROJECT_ROOT/target 2.17`