kernel-drobo5n
==============

Kernel source code for the Drobo5N

In the `kernel` folder:

```
source ../crosscompile.sh
make mrproper ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi-
cp ../config .config
make menuconfig ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi-
```

Pick the modules from the menu, and then:

```
make modules ARCH=arm CROSS_COMPILE=arm-none-linux-gnueabi- CFLAGS_MODULE="-DMODULE -mlong-calls"
find . -name "*.ko"
```

See the [releases](https://github.com/droboports/kernel-drobofs/releases) page for pre-compiled modules.
