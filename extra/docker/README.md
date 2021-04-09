# Pwntools Docker Images

This directory contains some Docker images with various versions of Pwntools pre-installed.

## Getting Images

You can either make them yourself, or pull from Docker Hub.

### Docker Hub

To pull an image from Docker hub, just run the command:

```sh
$ docker pull pwntools/pwntools:stable
```

Replace `stable` with `beta` or `dev` as desired.

### Building Locally

To build the images locally, just invoke the `Makefile` with the desired branch target.

```sh
$ make -C extra/docker dev
```

## Running Images

To run the `stable`, `beta`, or `dev` image, we recommend the following command line, in this example it is the `dev` image.

```sh
$ docker run -it \
    --privileged \
    --net=host \
 		--ulimit core=-1:-1 \
 		pwntools/pwntools:dev
```

The `--privileged` option is needed to perform any debugging with GDB.

The `--ulimit` option is needed for any corefiles to drop when a program crashes.

The `--net=host` allows you to easily connect to services hosted inside the container from outside the container.

## Development Dockerfile

In addition to `stable`, `beta`, and `dev` Dockerfiles, there is also a `develop` dockerfile which mounts your Pwntools installation inside the VM so you can develop seamlessly while editing on your host.

```sh
$ make -C extra/docker develop
```

You will be dropped into a shell, and any changes you make to your local Pwntools checkout will be immediately reflected inside the Docker container.  This is useful for e.g. editing on a macOS host, but testing your changes on Ubuntu without needing to copy files around.