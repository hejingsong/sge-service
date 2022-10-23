# 简介
一个简易的通用服务器。可以自定义消息处理，由底层做消息分发。使用libcontext作为异步任务调度，使用epoll/io_uring作为事件收发器。

# 编译
可以不指定`WITH_IOURING`选项，这样就不会编译io_uring库。
```bash
git submodule update --init
mkdir build && cd build
cmake -DWITH_IOURING=yes ..
make
make install
```
# example项目
## 介绍
该项目实现了一个简陋的http服务
## 编译
1. 需要修改python3-config路径 example/CMakeLists.txt
```bash
mkdir build && cd build
cmake ..
make
```
2. 运行成功之后会生成libpyhttp.so文件
## 运行项目
1. 修改example/config.ini文件，主要修改worker_dir和dir两个配置。
    1. worker_dir 表示该项目的工作目录
    2. dir表示libpyhttp.so 存放的目录
```
[core]
log_level = DEBUG
event_type = EPOLL
worker_dir = /home/hejs/Code/hejingsong/sge-service/example
modules = pyhttp

[pyhttp]
dir = /home/hejs/Code/hejingsong/sge-service/example/build
host = 0.0.0.0
port = 12345
```

### 运行
```bash
sge-service example/config.ini
```
