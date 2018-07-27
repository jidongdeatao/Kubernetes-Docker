Docker中可能会出现的安全问题
内核漏洞（Kernel exploits）
 容器是基于内核的虚拟化，主机（host）和主机上的所有容器共享一套内核。如果某个容器的操作造成了内核崩溃，那么反过来整台机器上的容器都会受到影响。
拒绝服务攻击（Denial-of-service attacks）
 所有的容器都共享了内核资源，如果一个容器独占了某一个资源（内存、CPU、各种ID），可能会造成其他容器因为资源匮乏无法工作（形成DoS攻击）。
容器突破（Container breakouts）
 Linux的namespace机制是容器的核心之一，它允许容器内部拥有一个PID=1的进程而在容器外部这个进程号又是不一样的（比如1234）。现在问题在于如果一个PID=1的进程突破了namespace的限制，那么他将会在主机上获得root权限。
有毒镜像（Poisoned images）
 主要是考虑到镜像本身的安全性，没太多好说的。
密钥获取（Compromising secrets）
 容器中的应用可能会获取一些容器外部的服务，这些服务之间可能会有密钥（secret key）等，如果因为密钥保存不当，那么这些服务对于攻击者来说就是可获取的了，这就会造成很多隐患。特别的，这样的问题如果出现在微服务架构中就特别严重。
安全方案
主机级别的隔离
 主机级别的隔离（Segregate Containers by Host）即将不同用户的容器放在不同的机器上、将那些存放了敏感数据的容器和普通的容器隔离开来、将哪些直接暴露给终端用户的容器（web容器）隔离开来。
 主机级别的隔离的好处是可以防止容器突破攻击、DoS攻击，但是这样的隔离会付出成本甚至性能的代价的。
关注镜像的安全

 通常，我们获取镜像的方式是从网络中(Docker hub)中pull，就像从网络上下载软件时下载方会提供一个SHA一样，我们也可以通过一个数字签名来查看下载的镜像是否安全。
 从1.8开始，Docker提供了一个数字签名机制——content trust来确保镜像来源的真实可靠。简单来说就是镜像制作者制作镜像时可以选择对镜像标签（tag）进行签名或者不签名，当我pull镜像时，就可以通过这个签名进行校验，如果一致则认为数据源可靠，并下载镜像。
 默认情况下，这个content trust是被关闭了的，你需要设置一个环境变量来开启这个机制,即：

export DOCKER_CONTENT_TRUST=1

    1

 当content trust机制被开启后，docker不会pull验证失败或者没有签名的镜像标签。当然也可以通过在pull时加上--disable-content-trust来暂时取消这个限制。
关于docker run的一些细节

 下面介绍一些在写Dockerfile时的一些细节或者在启动docker时的一些参数，这些细节或者参数可能用来提高安全性。
在容器中设置一个普通用户（User）

 容器中的应用最好不要以root用户身份运行，这是为了防止容器突破攻击。在实践中，建议在做Dockerfile的时候，要创建一个普通用户，然后切换到这个用户上来，比如：

RUN groupadd -r user_grp && useradd -r -g user_grp user
USER user

    1
    2

 或者在最后的入口点（entrypoint）中切换到普通用户上去,比如

#!/bin/bash
set -e
if [ "$1" = 'redis-server' ]; then
chown -R redis .
exec gosu redis "$@"
fi
exec "$@"

    1
    2
    3
    4
    5
    6
    7

 这里的gosu命令是docker建议在入口点用来代替sudo使用的命令。
 最后，如果非要在容器中使用root用户，建议使用SELinux来对容器进行约束。
限制容器的网络

 这个比较好理解，第一，容器应向外暴露尽可能少的端口，此外，对于容器之间的通信，最好是需要通信的容器才是连通的。
 对于第二点需要稍微解释一下，一般情况下，即使是容器端口关闭，容器之间还是可以相互通信的。为了避免这种情况，需要在docker服务(Docker daemon)启动时指定一个--icc = false标志位，这个标志位会关闭容器之间的这种通信。
移除SUID和SGID的二进制位

 SUID和SGID就是对于一些脚本文件,在执行（脚本）的时候拥有这个拥有者的权限，为了防止权限提升攻击（privilege escalation attack），我们需要尽可能的移除SUID和SGID的标志位（权限标志是按位来表示的）。
 一般情况下，我们更可能在Dockerfile中使用SUID和SGID的功能（为了在执行脚本文件时获取特root权限等..），所以建议就是最好在Dockerfile结束前去除这些标志位（当然要在前面说的切换用户之前）。一个例子如下：

FROM debian:wheezy
RUN find / -perm +6000 -type f -exec chmod a-s {} \; || true

    1
    2

限制内存

 这个自不用说，就是防止一个容器耗尽内存资源（DoS的一种吧？），一般使用-m以及--memory-swap标志位实现。

    注意，--memory-swap是等于内存加上交换内存的总容量！然后如果只是-m,那么缺省的--memory-swap就等于2倍-m,同样的，如果-m和--memory-swap的值设为一样，就默认了没有交换内存的空间，而且总的容量仅仅是--memory-swap的而不是二者之和。

限制CPU

 同样是防止CPU资源被耗尽（DoS），相应的启动参数是

    -c 默认值是1024,也就是一个权值,当-c为1024时,这个容器使用的cpu数量是(cpu总数/容器数量)，以此类推,当-c为2045时,这个值是2*(cpu总数/容器数量)通过以上设置，只会在 CPU 密集(繁忙)型运行进程时体现出来。当一个 container 空闲时，其它容器都是可以占用 CPU 的。
    –cpu-period + –cpu-quota 不同于上面的相对分配CPU，这两个参数合起来使用可以实现对cpu的绝对分配，具体可以参考一篇博客

限制重启

 容器如果不停地重启,也会消耗很多资源,造成DoS攻击,这个主要是在启动命令行时使用--restart=on-failure:10这样的参数，当然这里的10可以改成其他任意数字。
限制文件系统

 这个主要是防止在容器内的随意写（脚本）造成的攻击。即在启动时戴上--read-only参数。
限制能力（Capabilities）

 capabilities简单来说，就是开放给进程的权限（access），比如ping的时候就使用了socket。docker容器本质上就是一个进程，它默认有一些capabilities，例如：CHOWN, DAC_OVERRIDE, FSETID, FOWNER, MKNOD, NET_RAW, SETGID, SETUID, SETFCAP, SETPCAP,
NET_BIND_SERVICE, SYS_CHROOT, KILL, and AUDIT_WRITE（具体的可以 man capabilities）。一般情况下，可能需要根据业务增加capabilities（--cap-add），当然为了安全，可能需要先关掉所有的capabilities（--cap-drop all）再增加一些特定的capabilities。
使用资源限制

 基于Linux内核本身对程序的资源限制ulimit命令（别忘了docker容器本身是个进程），可以使用--ulimit标志来限制一些资源。主要的限制有cpu、nofile（最大文件描述符）、nproc（最大进程数），注意资源限制分为硬限制和软限制，硬限制资源一旦设置不能增加、软限制设置后可以增加，但是 不能超过硬限制数，格式为：

软限制[:硬限制]
如:docker run --ulimit cpu=12:14 amouat/stress stress --cpu 1
即,在使用了cpu12秒后杀死容器

    1
    2
    3

SELinux

 SELinux主要提供了强制访问控制（MAC），即不再是仅依据进程的所有者与文件资源的rwx权限来决定有无访问能力。能在攻击者实施了容器突破攻击后增加一层壁垒。建议在主机上开启SELinux。注意SELinux在红帽的Linux上是默认开启的，但是Ubuntu默认没有安装SElinux。
AppArmor

 SELinux算是蛮复杂的，经常都被人直接关掉。而AppArmor就相对要简单点，它将进程的权限与进程capabilities所联系在一起。docker官方也推荐这种方式。
总结

 考虑docker的安全性主要还是从以下几个方面出发

    docker本身的机制，即基于namespace进行隔离、cgroup进行资源限制、capabilities进行权限限制
    对于docker守护进程本身的攻击上
    在进行文件配置（做Dockerfile或者启动容器）时的疏漏
    Linux内核本身的安全特性

 整体来说，如果你将容器内的应用以非root身份运行，Docker 默认配置下是挺安全的。上面提到的也是在极端情况下的一些考虑，具体的，应该和现实的应用场景相结合。
