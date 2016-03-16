MAKE=make
WERROR_CFLAGS=
#KSRC = /usr/src/kernels/$(BUILD_KERNEL)
KSRC = /lib/modules/`uname -r`/build
obj-m := lwfw.o
lwfw:
	$(MAKE) -C $(KSRC) SUBDIRS=$(shell pwd) modules
clean:
	rm -rf *.ko *.o *.mod*