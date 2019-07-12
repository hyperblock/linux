#cflags-y += -I/usr/include/
#hyperblock-y := lsmt_ro_file.o
#obj-$(CONFIG_BLK_DEV_LOOP) += loop.o
obj-$(CONFIG_HYPERBLOCK) += hbloop.o 
hbloop-objs := src/hbloop.o src/lsmt_ro_file.o
#KERNEL_PATH=/root/kernel/hyperblock_loop
KERNEL_PATH=../../../

all: hbloop hbloop_ioctls

hbloop:
	make -C $(KERNEL_PATH) M=$(PWD) modules

hbloop_ioctls: hbloop_ioctls.o
	$(CC) $(CFLAGS) $(CLOOP_CFLAGS) $(LDFLAGS) -Wall -O2 -s -o $@ $<

clean:
	rm -rf  *.o *.ko Module.symvers  .tmp* modules.order *.mod.c


