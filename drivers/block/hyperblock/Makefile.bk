cflags-y += -I/usr/include/
#hyperblock-y := lsmt_ro_file.o
obj-$(CONFIG_BLK_DEV_LOOP)	+= loop.o
loop-objs := ./src/loop.o ./src/lsmt_ro_file.o
obj-$(CONFIG_HYPERBLOCK) 	+= 
KERNEL_PATH=/root/kernel/hyperblock_loop
all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
