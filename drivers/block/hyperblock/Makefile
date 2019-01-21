#cflags-y += -I/usr/include/
#hyperblock-y := lsmt_ro_file.o
#obj-$(CONFIG_BLK_DEV_LOOP) += loop.o
obj-$(CONFIG_HYPERBLOCK) += loop.o 
loop-objs := src/loop.o src/lsmt_ro_file.o
#KERNEL_PATH=/root/kernel/hyperblock_loop
KERNEL_PATH=../../../
all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
