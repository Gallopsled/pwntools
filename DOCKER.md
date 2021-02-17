# Using Pwntools with Docker

Sometimes it's annoying to set up Pwntools on your workstation, and you want something that Just Works (TM).

[Docker](https://www.docker.com/) is here to the rescue! Using Docker means that you get a nice, standardized Linux environment and don't need to worry about pip or installing dependencies.

## Quick Start

First, install Docker for your OS, which you can find on their [Getting Started](https://www.docker.com/get-started) page.

Next, download and run the Pwntools stable docker image.

```sh
$ docker run -it pwntools/pwntools:stable
```

## Recommended Settings

In order to get the most from your docker image, we need to enable debugging of processes (`--privileged`) and expose the network ports from the guest to the host (`--net=host`).

```sh
$ docker run -it \
    --privileged \
    --net=host \
    --hostname localhost \
    --ulimit core=-1:-1 \
    pwntools/pwntools:stable
```

## Sharing a Folder

It's really nice to be able to use your preferred native editor, and have the changes show up live inside your Docker image.  This is easy to add, thanks to Docker's bind mounts (`--mount type=bind`).  

With the command below, your `~/exploits` directory will magically show up inside the Docker image at `/home/pwntools/exploits` so that you can easily run them (from Docker) and edit them (from outside Docker).

```sh
$ mkdir $HOME/exploits

$ vim $HOME/exploits/my_exploit.py

$ docker run -it \
    --privileged \
    --net=host \
    --hostname localhost \
    --ulimit core=-1:-1 \
    --mount type=bind,source="$HOME/exploits",target=/home/pwntools/exploits \
    pwntools/pwntools:stable
    
$ python3 exploits/my_exploit.py
```

### Windows User Bind Mounts

If you're a Windows user `$HOME` doesn't exist in the same way as on Linux, instead it is `%UserProfile%`.  The command from above would look like this, assuming your editor is Visual Studio Code and you have code.exe in your `%PATH%`.

```sh
C:\Users\user> mkdir Desktop\exploits

C:\Users\user> code Desktop\exploits\my_exploit.py

C:\Users\user> docker run -it \
    --privileged \
    --net=host \
    --hostname localhost \
    --ulimit core=-1:-1 \
    --mount type=bind,source="%UserProfile%\Desktop\exploits",target=/home/pwntools/exploits \
    pwntools/pwntools:stable
    
$ python3 exploits/my_exploit.py

```





