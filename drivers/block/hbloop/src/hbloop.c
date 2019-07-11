

#define HBLOOP_NAME "hyperblock_loop"
#define HBLOOP_VERSION "1.0"
#define HBLOOP_MAX 8

#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME hyperblock_loop
#endif

#ifndef KBUILD_BASENAME
#define KBUILD_BASENAME hyperblock_loop
#endif

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/stat.h>
#include <linux/errno.h>
#include <linux/major.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <asm/div64.h> /* do_div() for 64bit division */
#include <asm/uaccess.h>
#include <asm/byteorder.h>
#include <linux/vfs.h> /* for vfs_read*/
#include <linux/types.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#include <linux/types.h>   /* u_int32_t */

#define HBLOOP_HEADROOM 128

/* Header of fixed length, can be located at beginning or end of file   */
struct hbloop_head
{
	char preamble[HBLOOP_HEADROOM];
	u_int32_t block_size;
	u_int32_t num_blocks;
};


typedef uint64_t hbloop_block_ptr;


struct hbloop_device
{
	/* Header filled from the file */
	struct hbloop_head head;
	int header_first;
	int file_format;

	/* An or'd sum of all flags of each compressed block (v3) */
	u_int32_t allflags;

	/* An array of cloop_ptr flags/offset for compressed blocks within the file */
	hbloop_block_ptr *block_ptrs;

	/* We buffer some uncompressed blocks for performance */
	size_t num_buffered_blocks;	/* how many uncompressed blocks buffered for performance */
	int *buffered_blocknum;        /* list of numbers of uncompressed blocks in buffer */
	int current_bufnum;            /* which block is current */
	unsigned char **buffer;        /* cache space for num_buffered_blocks uncompressed blocks */
	void *compressed_buffer;       /* space for the largest compressed block */
	size_t preload_array_size;     /* Size of pointer array in blocks */
	size_t preload_size;           /* Number of successfully allocated blocks */
	char **preload_cache;          /* Pointers to preloaded blocks */

	struct file   *backing_file;  /* associated file */
	struct inode  *backing_inode; /* for bmap */

	unsigned char *underlying_filename;
	unsigned long largest_block;
	unsigned int underlying_blksize;
	loff_t underlying_total_size;
	int hlo_number;
	int refcnt;
	struct block_device *bdev;
	int isblkdev;
	/* Lock for kernel block device queue */
	spinlock_t queue_lock;
	/* mutex for ioctl() */
	struct mutex hlo_ctl_mutex;
	struct list_head hlo_list;
	struct task_struct *hlo_thread;
	wait_queue_head_t hlo_event;
	struct request_queue *hlo_queue;
	struct gendisk *hlo_disk;
	int suspended;
};



#ifdef CONFIG_COMPAT
static int hbloop_compat_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	switch(cmd) {
		case LOOP_SET_CAPACITY: /* Change arg */ 
		case LOOP_CLR_FD:       /* Change arg */ 
		case LOOP_GET_STATUS64: /* Change arg */ 
		case LOOP_SET_STATUS64: /* Change arg */ 
			arg = (unsigned long) compat_ptr(arg);
		case LOOP_SET_STATUS:   /* unchanged */
		case LOOP_GET_STATUS:   /* unchanged */
		case LOOP_SET_FD:       /* unchanged */
		case LOOP_CHANGE_FD:    /* unchanged */
			return hbloop_ioctl(bdev, mode, cmd, arg);
			break;
	}
	return -ENOIOCTLCMD;
}
#endif



static int hbloop_open(struct block_device *bdev, fmode_t mode)
{
	int hbloop_num;
	if(!bdev) return -EINVAL;
	hbloop_num=MINOR(bdev->bd_dev);
	if(hbloop_num > hbloop_count-1) return -ENODEV;
	/* Allow write open for ioctl, but not for mount. */
	/* losetup uses write-open and flags=0x8002 to set a new file */
	if(mode & FMODE_WRITE)
	{
		printk(KERN_WARNING "%s: Can't open device read-write in mode 0x%x\n", hbloop_name, mode);
		return -EROFS;
	}
	hbloop_dev[hbloop_num]->refcnt+=1;
	return 0;
}


static void hbloop_close(struct gendisk *disk, fmode_t mode)
{
	int hbloop_num;
	if(!disk) return;
	hbloop_num=((struct hbloop_device *)disk->private_data)->hlo_number;
	if(hbloop_num < 0 || hbloop_num > (hbloop_count-1)) return;
	hbloop_dev[hbloop_num]->refcnt-=1;
}


static struct block_device_operations hlo_fops =
{
owner:		THIS_MODULE,
		open:           hbloop_open,
		release:        hbloop_close,
#ifdef CONFIG_COMPAT
		compat_ioctl:	hbloop_compat_ioctl,
#endif
		ioctl:          hbloop_ioctl
};





//alloc and init 
static int hbloop_alloc(int hbloop_num)
{
	struct hbloop_device *hlo = (struct hbloop_device *) hbloop_malloc(sizeof(struct hbloop_device));
	if(hlo == NULL) goto error_out;
	hbloop_dev[hbloop_num] = hlo;
	memset(clo, 0, sizeof(struct hbloop_device));
	hlo->hlo_number = hbloop_num;
	hlo->hlo_thread = NULL;
	init_waitqueue_head(&hlo->hlo_event);
	spin_lock_init(&hlo->queue_lock);
	mutex_init(&hlo->hlo_ctl_mutex);
	INIT_LIST_HEAD(&hlo->hlo_list);
	hlo->hlo_queue = blk_init_queue(hbloop_do_request, &hlo->queue_lock);
	if(!hlo->hlo_queue)
	{
		printk(KERN_ERR "%s: Unable to alloc queue[%d]\n", hbloop_name, hbloop_num);
		goto error_out;
	}
	hlo->hlo_queue->queuedata = hlo;
	hlo->hlo_disk = alloc_disk(1);
	if(!hlo->hlo_disk)
	{
		printk(KERN_ERR "%s: Unable to alloc disk[%d]\n", hbloop_name, hbloop_num);
		goto error_disk;
	}
	hlo->hlo_disk->major = hbloop_major;
	hlo->hlo_disk->first_minor = hbloop_num;
	hlo->hlo_disk->fops = &hlo_fops;
	hlo->hlo_disk->queue = hlo->hlo_queue;
	hlo->hlo_disk->private_data = hlo;
	sprintf(hlo->hlo_disk->disk_name, "%s%d", hbloop_name, hbloop_num);
	add_disk(hlo->hlo_disk);
	return 0;
error_disk:
	blk_cleanup_queue(hlo->hlo_queue);
error_out:
	return -ENOMEM;
}



static void hbloop_dealloc(int hbloop_num)
{
	struct hbloop_device *hlo = hbloop_dev[hbloop_num];
	if(hlo == NULL) return;
	del_gendisk(hlo->hlo_disk);
	blk_cleanup_queue(hlo->hlo_queue);
	put_disk(hlo->hlo_disk);
	hbloop_free(hlo, sizeof(struct hbloop_device));
	hbloop_dev[hbloop_num] = NULL;
}





static int __init hbloop_init(void)
{
	int error=0;
	printk("%s: Initializing %s v"HBLOOP_VERSION"\n",hbloop_name, hbloop_name);
	hbloop_dev = (struct hbloop_device **)hbloop_malloc(hbloop_max * sizeof(struct hbloop_device *));
	if(hbloop_dev == NULL) return -ENOMEM;
	memset(hbloop_dev, 0, hbloop_max * sizeof(struct hbloop_device *));
	hbloop_count=0;
	hbloop_major=MAJOR_NR;

	if(register_blkdev(MAJOR_NR, hbloop_name))
	{
		printk(KERN_WARNING "%s: Unable to get major device %d\n", hbloop_name,
				MAJOR_NR);
		/* Try dynamic allocation */
			if((hbloop_major=register_blkdev(0,hbloop_name))<0)
		{
			printk(KERN_ERR "%s: Unable to get dynamic major device\n", hbloop_name);
			error = -EIO;
			goto init_out_hbloop_free;
		}
		printk(KERN_INFO "%s: Got dynamic major device %d, "
				"mknod /dev/%s b %d 0\n",
				hbloop_name, hbloop_major, hbloop_name, hbloop_major);
	}
	while(hbloop_count<hbloop_max)
		if((error=hbloop_alloc(hbloop_count))!=0) break; else ++hbloop_count;
	if(!hbloop_count) goto init_out_dealloc;
	printk(KERN_INFO "%s: loaded (max %d devices)\n", hbloop_name, hbloop_count);

#if 0
	if(file) /* global file name for first cloop-Device is a module option string. */
	{
		int namelen = strlen(file);
		if(namelen<1 ||
				(initial_file=filp_open(file,O_RDONLY|O_LARGEFILE,0x00))==NULL ||
				IS_ERR(initial_file))
		{
			error=PTR_ERR(initial_file);
			if(!error) error=-EINVAL;
			initial_file=NULL; /* if IS_ERR, it's NOT open. */
		}
		else
			error=hbloop_set_file(0,initial_file);
		if(error)
		{
			printk(KERN_ERR
					"%s: Unable to get file %s for cloop device, error %d\n",
					hbloop_name, file, error);
			goto init_out_dealloc;
		}
	}
#endif 
	return 0;
init_out_dealloc:
	while (hbloop_count>0) hbloop_dealloc(--hbloop_count);
	unregister_blkdev(hbloop_major, hbloop_name);
init_out_cloop_free:
	hbloop_free(hbloop_dev, hbloop_max * sizeof(struct hbloop_device *));
	hbloop_dev = NULL;
	return error;
}

static void __exit hbloop_exit(void)
{
	int error=0;
	unregister_blkdev(hbloop_major,hbloop_name);	
	while(hbloop_count>0)
	{
		--hbloop_count;
		if(hbloop_dev[hbloop_count]->backing_file) hbloop_clr_fd(hbloop_count, NULL);
		hbloop_dealloc(hloop_count);
	}
	printk("%s: unloaded.\n", hloop_name);
}

/* The cloop init and exit function registration (especially needed for Kernel 2.6) */
module_init(hbloop_init);
module_exit(hbloop_exit);

#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
