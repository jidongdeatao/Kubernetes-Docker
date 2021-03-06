入门学习Docker可以看一下阮一峰的博文：
http://www.ruanyifeng.com/blog/2018/02/docker-tutorial.html

Docker简介：
    Linux 有一种虚拟化技术：Linux 容器（Linux Containers，缩写为 LXC）。
    Linux 容器不是模拟一个完整的操作系统，而是对进程进行隔离。或者说，在正常进程的外面套了一个保护层。对于容器里面的进程来说，它接触到的各种资源
    都是虚拟的，从而实现与底层系统的隔离。
    由于容器是进程级别的，相比虚拟机有很多优势。

 
Docker安装：
参照Docker安装指南

安装完成后，运行下面的命令，验证是否安装成功。
    $ docker version # 或者 $ docker info
Docker 需要用户具有 sudo 权限，为了避免每次命令都输入sudo，可以把用户加入 Docker 用户组（官方文档）。
    $ sudo usermod -aG docker $USER
Docker 是服务器----客户端架构。命令行运行docker命令的时候，需要本机有 Docker 服务。如果这项服务没有启动，可以用下面的命令启动（官方文档）。
    # service 命令的用法
    $ sudo service docker start

    # systemctl 命令的用法
    $ sudo systemctl start docker

六、image 文件
Docker 把应用程序及其依赖，打包在 image 文件里面。只有通过这个文件，才能生成 Docker 容器。image 文件可以看作是容器的模板。Docker 根据 image
文件生成容器的实例。同一个 image 文件，可以生成多个同时运行的容器实例。

image 是二进制文件。实际开发中，一个 image 文件往往通过继承另一个 image 文件，加上一些个性化设置而生成。举例来说，你可以在 Ubuntu 的 image 
基础上，往里面加入 Apache 服务器，形成你的 image。   
    $ docker image ls # 列出本机的所有 image 文件。
    $ docker image rm [imageName] # 删除 image 文件
    
七、实例：hello world
国内连接 Docker 的官方仓库很慢，还会断线，需要将默认仓库改成国内的镜像网站，具体的修改方法:
这里推荐使用官方镜像 registry.docker-cn.com 。下面是我的 Debian 系统的默认仓库修改方法，其他系统的修改方法参考官方文档。
打开/etc/default/docker文件（需要sudo权限），在文件的底部加上一行。
    DOCKER_OPTS="--registry-mirror=https://registry.docker-cn.com"
然后，重启 Docker 服务。
    $ sudo service docker restart

现在就会自动从镜像仓库下载 image 文件了。
首先，运行下面的命令，将 image 文件从仓库抓取到本地。
    $ docker image pull library/hello-world
上面代码中，docker image pull是抓取 image 文件的命令。library/hello-world是 image 文件在仓库里面的位置，其中library是 image 文件所在的组，hello-world是 image 文件的名字。

由于 Docker 官方提供的 image 文件，都放在library组里面，所以它的是默认组，可以省略。因此，上面的命令可以写成下面这样。
    $ docker image pull hello-world
抓取成功以后，就可以在本机看到这个 image 文件了。
    $ docker image ls
现在，运行这个 image 文件。
    $ docker container run hello-world     #docker container run命令会从 image 文件，生成一个正在运行的容器实例。
    注意，docker container run命令具有自动抓取 image 文件的功能。如果发现本地没有指定的 image 文件，就会从仓库自动抓取。因此，
    前面的docker image pull命令并不是必需的步骤。
    
有些容器不会自动终止，因为提供的是服务。比如，安装运行 Ubuntu 的 image，就可以在命令行体验 Ubuntu 系统。
    $ docker container ls
    $ docker container run -it ubuntu bash
对于那些不会自动终止的容器，必须使用docker container kill 命令手动终止。
    $ docker container kill [containID]
    终止运行的容器文件，依然会占据硬盘空间，可以使用docker container rm命令删除。
    $ docker container rm [containerID]
    运行上面的命令之后，再使用docker container ls --all命令，就会发现被删除的容器文件已经消失了。
    
九、Dockerfile 文件
学会使用 image 文件以后，接下来的问题就是，如何可以生成 image 文件？如果你要推广自己的软件，势必要自己制作 image 文件。
这就需要用到 Dockerfile 文件。它是一个文本文件，用来配置 image。Docker 根据 该文件生成二进制的 image 文件。
下面通过一个实例，演示如何编写 Dockerfile 文件。
    实例：制作自己的 Docker 容器

下面我以 koa-demos 项目为例，介绍怎么写 Dockerfile 文件，实现让用户在 Docker 容器里面运行 Koa 框架。

作为准备工作，请先下载源码。
    $ git clone https://github.com/ruanyf/koa-demos.git
    $ cd koa-demos
10.1 编写 Dockerfile 文件
首先，在项目的根目录下，新建一个文本文件.dockerignore，写入下面的内容。
    .git
    node_modules
    npm-debug.log
上面代码表示，这三个路径要排除，不要打包进入 image 文件。如果你没有路径要排除，这个文件可以不新建。然后，在项目的根目录下，新建一个文本文件 Dockerfile，写入下面的内容。
    FROM node:8.4
    COPY . /app
    WORKDIR /app
    RUN npm install --registry=https://registry.npm.taobao.org
    EXPOSE 3000

上面代码一共五行，含义如下。
        FROM node:8.4：该 image 文件继承官方的 node image，冒号表示标签，这里标签是8.4，即8.4版本的 node。
        COPY . /app：将当前目录下的所有文件（除了.dockerignore排除的路径），都拷贝进入 image 文件的/app目录。
        WORKDIR /app：指定接下来的工作路径为/app。
        RUN npm install：在/app目录下，运行npm install命令安装依赖。注意，安装后所有的依赖，都将打包进入 image 文件。
        EXPOSE 3000：将容器 3000 端口暴露出来， 允许外部连接这个端口。
10.2 创建 image 文件
有了 Dockerfile 文件以后，就可以使用docker image build命令创建 image 文件了。
    $ docker image build -t koa-demo .
    # 或者
    $ docker image build -t koa-demo:0.0.1 .
上面代码中，-t参数用来指定 image 文件的名字，后面还可以用冒号指定标签。如果不指定，默认的标签就是latest。最后的那个点表示 Dockerfile 
文件所在的路径，上例是当前路径，所以是一个点。
如果运行成功，就可以看到新生成的 image 文件koa-demo了。
    $ docker image ls

10.3 生成容器
docker container run命令会从 image 文件生成容器。
    $ docker container run -p 8000:3000 -it koa-demo /bin/bash
    # 或者
    $ docker container run -p 8000:3000 -it koa-demo:0.0.1 /bin/bash
上面命令的各个参数含义如下：
        -p参数：容器的 3000 端口映射到本机的 8000 端口。
        -it参数：容器的 Shell 映射到当前的 Shell，然后你在本机窗口输入的命令，就会传入容器。
        koa-demo:0.0.1：image 文件的名字（如果有标签，还需要提供标签，默认是 latest 标签）。
        /bin/bash：容器启动以后，内部第一个执行的命令。这里是启动 Bash，保证用户可以使用 Shell。
如果一切正常，运行上面的命令以后，就会返回一个命令行提示符。
    root@66d80f4aaf1e:/app#
这表示你已经在容器里面了，返回的提示符就是容器内部的 Shell 提示符。执行下面的命令。
    root@66d80f4aaf1e:/app# node demos/01.js
这时，Koa 框架已经运行起来了。打开本机的浏览器，访问 http://127.0.0.1:8000，网页显示"Not Found"，这是因为这个 demo 没有写路由。
这个例子中，Node 进程运行在 Docker 容器的虚拟环境里面，进程接触到的文件系统和网络接口都是虚拟的，与本机的文件系统和网络接口是隔离的，
因此需要定义容器与物理机的端口映射（map）。

现在，在容器的命令行，按下 Ctrl + c 停止 Node 进程，然后按下 Ctrl + d （或者输入 exit）退出容器。此外，也可以用docker container kill终止容器运行。
    # 在本机的另一个终端窗口，查出容器的 ID
    $ docker container ls
    # 停止指定的容器运行
    $ docker container kill [containerID]
容器停止运行之后，并不会消失，用下面的命令删除容器文件。
    # 查出容器的 ID
    $ docker container ls --all
    # 删除指定的容器文件
    $ docker container rm [containerID]
    
也可以使用docker container run命令的--rm参数，在容器终止运行后自动删除容器文件。
    $ docker container run --rm -p 8000:3000 -it koa-demo /bin/bash

10.4 CMD 命令
上一节的例子里面，容器启动以后，需要手动输入命令node demos/01.js。我们可以把这个命令写在 Dockerfile 里面，这样容器启动以后，
这个命令就已经执行了，不用再手动输入了。
    FROM node:8.4
    COPY . /app
    WORKDIR /app
    RUN npm install --registry=https://registry.npm.taobao.org
    EXPOSE 3000
    CMD node demos/01.js
上面的 Dockerfile 里面，多了最后一行CMD node demos/01.js，它表示容器启动后自动执行node demos/01.js。
你可能会问，RUN命令与CMD命令的区别在哪里？简单说，RUN命令在 image 文件的构建阶段执行，执行结果都会打包进入 image 文件；
CMD命令则是在容器启动后执行。另外，一个 Dockerfile 可以包含多个RUN命令，但是只能有一个CMD命令。
注意，指定了CMD命令以后，docker container run命令就不能附加命令了（比如前面的/bin/bash），否则它会覆盖CMD命令。
现在，启动容器可以使用下面的命令。
    $ docker container run --rm -p 8000:3000 -it koa-demo:0.0.1

10.5 发布 image 文件
容器运行成功后，就确认了 image 文件的有效性。这时，我们就可以考虑把 image 文件分享到网上，让其他人使用。
首先，去 hub.docker.com 或 cloud.docker.com 注册一个账户。然后，用下面的命令登录。
    $ docker login
接着，为本地的 image 标注用户名和版本。
    $ docker image tag [imageName] [username]/[repository]:[tag]
    # 实例
    $ docker image tag koa-demos:0.0.1 ruanyf/koa-demos:0.0.1
也可以不标注用户名，重新构建一下 image 文件。
    $ docker image build -t [username]/[repository]:[tag] .
最后，发布 image 文件。
    $ docker image push [username]/[repository]:[tag]
发布成功以后，登录 hub.docker.com，就可以看到已经发布的 image 文件。

十一、其他有用的命令
docker 的主要用法就是上面这些，此外还有几个命令，也非常有用。
（1）docker container start
前面的docker container run命令是新建容器，每运行一次，就会新建一个容器。同样的命令运行两次，就会生成两个一模一样的容器文件。
如果希望重复使用容器，就要使用docker container start命令，它用来启动已经生成、已经停止运行的容器文件。
   $ docker container start [containerID]
（2）docker container stop
前面的docker container kill命令终止容器运行，相当于向容器里面的主进程发出 SIGKILL 信号。
而docker container stop命令也是用来终止容器运行，相当于向容器里面的主进程发出 SIGTERM 信号，然后过一段时间再发出 SIGKILL 信号。
    $ bash container stop [containerID]
这两个信号的差别是，应用程序收到 SIGTERM 信号以后，可以自行进行收尾清理工作，但也可以不理会这个信号。如果收到 SIGKILL 信号，就会强行立即终止，那些正在进行中的操作会全部丢失。
（3）docker container logs
docker container logs命令用来查看 docker 容器的输出，即容器里面 Shell 的标准输出。如果docker run命令运行容器的时候，没有使用-it参数，就要用这个命令查看输出。
    $ docker container logs [containerID]
（4）docker container exec
docker container exec命令用于进入一个正在运行的 docker 容器。如果docker run命令运行容器的时候，没有使用-it参数，就要用这个命令进入容器。
一旦进入了容器，就可以在容器的 Shell 执行命令了。
    $ docker container exec -it [containerID] /bin/bash
（5）docker container cp
docker container cp命令用于从正在运行的 Docker 容器里面，将文件拷贝到本机。下面是拷贝到当前目录的写法。
    $ docker container cp [containID]:[/path/to/file] .


