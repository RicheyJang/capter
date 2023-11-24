# Capter

## 环境

Cmake 3.21+ 、C++ 11

依赖：[`libpcap`](https://www.tcpdump.org/index.html#documentation)(1.10+)、[`spdlog`](https://github.com/gabime/spdlog#compiled-version-recommended---much-faster-compile-times)

通过包管理器安装依赖：

```shell
sudo apt install -y libpcap-dev libspdlog-dev
```

通过源码安装请自行查看上述库的官方文档，且记得将动态\静态链接库文件软链接至`/usr/lib`目录下

## 编译

```shell
mkdir build && cd build
cmake .. -G "Unix Makefiles" && make -j
```
