### libice
libice是一个c/c++类库，它实现了RFC5245规范定义的交互式连接建立协议, 该协议将交互式连接建立(ICE)定义为一种通过offer/answer模型建立的UDP媒体流的NAT穿越技术。该库的代码实现主要参考了WebRTC的相关模块。WebRTC是Google开源的一个音视频实时通信项目。

### 示例Demo
使用libice开发的一个1v1音视频实时通话示例demo: https://www.str2num.com/demos/videochat

### ICE(Interactive Connectivity Establishment)简介
RFC5245规范将ICE定义为: 一种通过offer/answer模型建立的UDP(尽管可以扩展到其它的协议，比如TCP)媒体流的NAT穿越技术。ICE是offer/answer模型的扩展，它通过在SDP的offer和answer中包含多个IP地址和端口，然后对这些IP地址和端口进行点到点的连通性检查来进行工作。SDP中包含的IP地址和端口以及进行连通性检查将使用修订的STUN规范，这个规范定义在RFC5389当中，并重命名为Session Traversal Utilities for NAT。新名称和新规范反映了STUN只是用于其它NAT穿越技术(ICE)的一个工具，而不是原来的STUN规范定义的作为一个独立的NAT穿越解决方案。ICE也使用NAT中继穿越TURN，该规范定义在RFC5766，它是STUN的扩展。由于ICE为每个媒体流交换了多个IP地址和端口，因此它允许为多宿主和双栈主机选择地址，并且不赞成使用RFC4091和RFC4092。

一个典型的ICE部署场景：
<pre>
                              +-------+
                              | SIP   |
           +-------+          | Srvr  |          +-------+
           | STUN  |          |       |          | STUN  |
           | Srvr  |          +-------+          | Srvr  |
           |       |         /         \         |       |
           +-------+        /           \        +-------+
                           /             \
                          /               \
                         /                 \
                        /                   \
                       /  <-  Signaling  ->  \
                      /                       \
                     /                         \
               +--------+                   +--------+
               |  NAT   |                   |  NAT   |
               +--------+                   +--------+
                 /                                \
                /                                  \
               /                                    \
           +-------+                             +-------+
           | Agent |                             | Agent |
           |   L   |                             |   R   |
           |       |                             |       |
           +-------+                             +-------+

</pre>
ICE的主要工作就是在Agent L和Agent R之间，找到一条或者多条路径，使得L和R可以实时通信。

### libice特点
由于本库的实现主要是为了满足在服务端转发WebRTC媒体流，而一般对外提供服务的服务器都有公网IP地址，所以该库的实现主要基于通信的两个peer要么位于同一个局域网，要么至少一个peer不在NAT后面。同时根据实际情况，对RFC5245定义的功能在实现上有所取舍。

与另外一个ICE实现库libnice相比，libnice依赖一个比较庞大的glib库，整个库显得比较重，编译安装非常麻烦，并且接口使用也不是很简洁。libice则主要参考了WebRTC的实现，只引入了小巧的libev作为网络事件库，整个库比较小巧，编译安装简单，接口使用也很方便, 同时代码量也不大，学习也比较简单。

### 相关RFC规范
+ [RFC5245] ICE协议: https://tools.ietf.org/html/rfc5245
+ [RFC5389] STUN协议: https://tools.ietf.org/html/rfc5389
+ [RFC5766] TURN协议: https://tools.ietf.org/html/rfc5766

### 要求
+ 目前仅适用于Linux平台
+ gcc版本建议使用gcc-4.8.4及其更高版本, 该库使用了大量的c++11语法，gcc版本过低将无法编译通过
+ 依赖libev-4.22或者以上版本
+ openssl版本不低于1.0.0

### 编译安装
#### 编译工具
本库的编译采用了buildmake工具，可以帮助你生成Makefile文件，buildmake是一个使用非常简单的编译环境构建工具，推荐使用。
buildmake使用教程：https://github.com/str2num/buildmake

#### 编译步骤
```shell
# 在你的工作目录下，建立一个目录
mkdir -p libice/str2num

# 进入建立的目录
cd libice/str2num

# 获取代码
git clone https://github.com/str2num/libice.git

# 修改项目根目录下的BUILDMAKE文件
vim BUILDMAKE
BUILDMAKE_BIN_PATH('~/opensource/buildmake/buildmake') # 该选项路径务必修改为你自己机器上的buildmake工具执行路径

# 执行buildmake命令
# libice库依赖另外一个git项目librtcbase，-U选项可以帮助你获取librtcbase库 -B表示执行编译
# 需要注意的是：librtcbase依赖libev, librtcbase在编译过程遇到问题，请参考https://github.com/str2num/librtcbase
buildmake -UB 

# 执行make, make成功之后会在项目根目录生成一个output，output目录包含libice的库文件
make

```

### 说明
+ 该库在Ubuntu 16.04.4 LTS、Ubuntu 14.04、CentOS release 6.5等平台编译通过，并正常使用。
+ gcc-4.8.4, gcc-5.4.0已验证编译通过。
+ 该库移植于Google的WebRTC项目，功能已经过了严格的单元测试, 所以该项目没有提供单元测试用例。
+ 后续会持续跟进WebRTC项目的最新进展，同时该库也会相应的持续维护和更新。

### 示例
+ 在项目的example目录，有一个示例demo，使用libice库实现了一个简单版的1v1消息聊天软件。
+ 一个1v1实时音视频通话的demo。https://www.str2num.com/demos/videochat

### 帮助文档
该库的帮助文档，正在积极建设当中，敬请期待, 谢谢！

### 贡献者
ji_wei8888@163.com
