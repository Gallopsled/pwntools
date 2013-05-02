Installation
============

You need Mton (http://mlton.org) and PreML (https://github.com/mortenbp/PreML)
to compile `crop`.  Directions below was tested on Ubuntu 12.10.

Installing MLton
----------------

```command
sudo apt-get install mlton
```

Installing PreML
----------------

```command
git clone git://github.com/mortenbp/PreML.git
cd PreML
make
sudo make install
```

Compiling `crop`
----------------

Go to the `crop/` directory and type

```command
make
```
