# Introduction
A simple general purpose server. Message processing can be customized, and message distribution is done by the bottom layer. Use libcontext as asynchronous task scheduling, and epoll/io_uring as event transceiver.

# Build
## Pre
checkout submodule
```bash
git submodule update --init
```

## Compile
```bash
mkdir build && cd build
cmake ..
make
make install
```

### Compile with io_uring
The default event manager is epoll, you can also use io_uring
```bash
mkdir build && cd build
cmake -DWITH_IO_URING=1 ..
make
make install
```

# example
## Introduction
a simple http server
## Build
```bash
mkdir build && cd build
cmake -DPY_CONFIG=python-config ..
make
```
After successful compilation, the libpyhttp.so file will be generated

## Config
1. Modify the example/config.ini file
```
[core]
log_level = DEBUG
modules = pyhttp
daemonize = 0

[pyhttp]
workspace = your workspace
dldir = libpyhttp.so directory
event = EPOLL
server = 0.0.0.0:12345
```

## Run
```bash
sge-service example/pyhttp/config.ini
```

# TODO
1. io_uring event management is not yet stable
