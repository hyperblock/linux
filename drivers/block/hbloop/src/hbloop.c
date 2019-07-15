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


#include "hbloop.h"



#define HBLOOP_NAME "hyperblock_loop"
#define HBLOOP_VERSION "1.0"
#define HBLOOP_MAX 8

#define MAJOR_NR 240
#if 0
#define DEBUGP printk
#else
#define DEBUGP(format, x...)
#endif

static int hbloop_major=MAJOR_NR;
static struct hbloop_device **hbloop_dev;
static const char *hbloop_name=HBLOOP_NAME;
static int hbloop_count = 0;




static void *hbloop_malloc(size_t size)
{
	return (void *)kvmalloc(size, GFP_KERNEL);

}

static void hbloop_free(void *mem, size_t size)
{
	kfree(mem);
}

static ssize_t hbloop_read_from_file(struct hbloop_device *clo, struct file *f, char *buf,
		loff_t pos, size_t buf_len)
{
	size_t buf_done=0;
	while (buf_done < buf_len)
	{
		size_t size = buf_len - buf_done, size_read;
		/* kernel_read() only supports 32 bit offsets, so we use vfs_read() instead. */
		/* int size_read = kernel_read(f, pos, buf + buf_done, size); */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4,14,14)
		mm_segment_t old_fs = get_fs();
		set_fs(get_ds());
		size_read = vfs_read(f, (void __user *)(buf + buf_done), size, &pos);
		set_fs(old_fs);
#else
		size_read = kernel_read(f, (void __user *)(buf + buf_done), size, &pos);
#endif
		if(size_read <= 0)
		{
			printk(KERN_ERR "%s: Read error %d at pos %llu in file %s, "
					"%d bytes lost.\n", hbloop_name, (int)size_read, pos,
					file, (int)size);
			memset(buf + buf_len - size, 0, size);
			break;
		}
		buf_done += size_read;
	}
	return buf_done;
}

/* This function does all the real work. */
/* returns "uptodate"                    */
static int hbloop_handle_request(struct hbloop_device *hlo, struct request *rq)
{
	int buffered_blocknum = -1;
	int preloaded = 0;
	//loff_t offset     = (loff_t) blk_rq_pos(req)<<9; /* req->sector<<9 */
	loff_t pos = ((loff_t) blk_rq_pos(rq) << 9) + lo->lo_offset;


	int res;
	struct bio_vec bvec;
	struct req_iterator iter;
	rq_for_each_segment(bvec, rq, iter)
	{
		unsigned long len = bvec.bv_len;
		char *to_ptr      = kmap(bvec.bv_page) + bvec.bv_offset;
		res=lsmt_pread(lsmt_file, to_ptr, len, pos);
		if (res < 0)
			return res;
		kunmap(bvec.bv_page);
	} /* end rq_for_each_segment*/
	return 0;
}

/* Adopted from loop.c, a kernel thread to handle physical reads */
static int hbloop_thread(void *data)
{
	struct hbloop_device *hlo = data;
	current->flags |= PF_NOFREEZE;
	set_user_nice(current, 10);
	while (!kthread_should_stop()||!list_empty(&hlo->hlo_list))
	{
		int err;
		err = wait_event_interruptible(hlo->hlo_event, !list_empty(&hlo->hlo_list) || 
				kthread_should_stop());
		if(unlikely(err))
		{
			DEBUGP(KERN_ERR "hbloop thread activated on error!? Continuing.\n");
			continue;
		}
		if(!list_empty(&hlo->hlo_list))
		{
			struct request *req;
			unsigned long flags;
			int uptodate;
			spin_lock_irq(&hlo->queue_lock);
			req = list_entry(hlo->hlo_list.next, struct request, queuelist);
			list_del_init(&req->queuelist);
			spin_unlock_irq(&hlo->queue_lock);
			uptodate = hbloop_handle_request(hlo, req);
			spin_lock_irqsave(&hlo->queue_lock, flags);
			__blk_end_request_all(req, uptodate ? 0 : -EIO);
			spin_unlock_irqrestore(&hlo->queue_lock, flags);
		}
	}
	DEBUGP(KERN_ERR "hbloop_thread exited.\n");
	return 0;
}

/* This is called by the kernel block queue management every now and then,
 * with successive read requests qeued and sorted in a (hopefully)
 * "most efficient way". spin_lock_irq() is being held by the kernel. */
static void hbloop_do_request(struct request_queue *q)
{
	struct request *rq;
	while((rq = blk_fetch_request(q)) != NULL)
	{
		struct hbloop_device *hlo;
		int rw;
		/* quick sanity checks */
		/* blk_fs_request() was removed in 2.6.36 */
		if (unlikely(rq == NULL))
			goto error_continue;
		rw = rq_data_dir(rq);
		if (unlikely(rw != READ))
		{
			DEBUGP("hbloop_do_request: bad command\n");
			goto error_continue;
		}
		hlo = rq->rq_disk->private_data;
		if (unlikely(!hlo->backing_file && !hlo->suspended))
		{
			DEBUGP("hbloop_do_request: not connected to a file\n");
			goto error_continue;
		}
		//add rq to working list
		list_add_tail(&rq->queuelist, &hlo->hlo_list); /* Add to working list for thread */
		wake_up(&hlo->hlo_event);    /* Wake up hbloop_thread */
		continue; /* next request */
error_continue:
		DEBUGP(KERN_ERR "hbloop_do_request: Discarding request %p.\n", rq);
		__blk_end_request_all(rq, -EIO);
	}
}

/* Read header, flags and offsets from already opened file */
static int hbloop_set_file(int hbloop_num, struct file *file)
{
	struct hbloop_device *hlo = hbloop_dev[hbloop_num];
	struct inode *inode;
	char *bbuf=NULL;
	unsigned int bbuf_size = 0;
	const unsigned int header_size = sizeof(struct hbloop_head);
	unsigned int i, offsets_read=0, total_offsets=0;
	loff_t fs_read_position = 0, header_pos[2];
	int isblkdev, bytes_read, error = 0;
	if (hlo->suspended) return error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
	inode = file->f_dentry->d_inode;
	clo->underlying_filename = kstrdup(file->f_dentry->d_name.name ? file->f_dentry->d_name.name : (const unsigned char *)"anonymous filename", GFP_KERNEL);
#else
	inode = file->f_path.dentry->d_inode;
	clo->underlying_filename = kstrdup(file->f_path.dentry->d_name.name ? file->f_path.dentry->d_name.name : (const unsigned char *)"anonymous filename", GFP_KERNEL);
#endif
	isblkdev=S_ISBLK(inode->i_mode)?1:0;
	if(!isblkdev&&!S_ISREG(inode->i_mode))
	{
		printk(KERN_ERR "%s: %s not a regular file or block device\n",
				hbloop_name, clo->underlying_filename);
		error=-EBADF; goto error_release;
	}
	clo->backing_file = file;
	clo->backing_inode= inode ;
	clo->underlying_total_size = (isblkdev) ? inode->i_bdev->bd_inode->i_size : inode->i_size;
	if(clo->underlying_total_size < header_size)
	{
		printk(KERN_ERR "%s: %llu bytes (must be >= %u bytes)\n",
				hbloop_name, clo->underlying_total_size,
				(unsigned int)header_size);
		error=-EBADF; goto error_release;
	}
	if(isblkdev)
	{
		struct request_queue *q = bdev_get_queue(inode->i_bdev);
		blk_queue_max_hw_sectors(clo->clo_queue, queue_max_hw_sectors(q)); /* Renamed in 2.6.34 */
		blk_queue_max_segments(clo->clo_queue, queue_max_segments(q)); /* Renamed in 2.6.34 */
		/* blk_queue_max_hw_segments(clo->clo_queue, queue_max_hw_segments(q)); */ /* Removed in 2.6.34 */
		blk_queue_max_segment_size(clo->clo_queue, queue_max_segment_size(q));
		blk_queue_segment_boundary(clo->clo_queue, queue_segment_boundary(q));
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		blk_queue_merge_bvec(clo->clo_queue, q->merge_bvec_fn);
#endif
		clo->underlying_blksize = block_size(inode->i_bdev);
	}
	else
		clo->underlying_blksize = PAGE_SIZE;

	DEBUGP(KERN_INFO "Underlying blocksize of %s is %u\n", clo->underlying_filename, clo->underlying_blksize);
	DEBUGP(KERN_INFO "Underlying total size of %s is %llu\n", clo->underlying_filename, clo->underlying_total_size);

	/* clo->underlying_blksize should be larger than header_size, even if it's only PAGE_SIZE */
	bbuf_size = clo->underlying_blksize;
	bbuf = hbloop_malloc(bbuf_size);
	if(!bbuf)
	{
		printk(KERN_ERR "%s: out of kernel mem for buffer (%u bytes)\n",
				hbloop_name, (unsigned int) bbuf_size);
		error=-ENOMEM; goto error_release;
	}

	set_capacity(clo->clo_disk, (sector_t)(clo->head.num_blocks*(clo->head.block_size>>9)));
	clo->clo_thread = kthread_create(hbloop_thread, clo, "hbloop%d", hbloop_num);
	if(IS_ERR(clo->clo_thread))
	{
		error = PTR_ERR(clo->clo_thread);
		clo->clo_thread=NULL;
		goto error_release_free_all;
	}
	wake_up_process(clo->clo_thread);
	/* Uncheck */
	return error;
error_release:
	if(bbuf) hbloop_free(bbuf, clo->underlying_blksize);
	if(clo->underlying_filename) { kfree(clo->underlying_filename); clo->underlying_filename=NULL; }
	clo->backing_file=NULL;
	return error;
}



/* Get file from ioctl arg (only losetup) */
static int hbloop_set_fd(int hbloop_num, struct file *hlo_file,
		struct block_device *bdev, unsigned int arg)
{
	struct hbloop_device *hlo = hbloop_dev[hbloop_num];
	struct file *file=NULL;
	int error = 0;

	/* Already an allocated file present */
	if(hlo->backing_file) return -EBUSY;
	file = fget(arg); /* get filp struct from ioctl arg fd */
	if(!file) return -EBADF;
	error=hbloop_set_file(hbloop_num,file);
	set_device_ro(bdev, 1);
	if(error) fput(file);
	return error;
}



/* Drop file and free buffers, both ioctl and initial_file */
static int hbloop_clr_fd(int hbloop_num, struct block_device *bdev)
{
	struct hbloop_device *hlo = hbloop_dev[hbloop_num];
	struct file *filp = hlo->backing_file;
	if(hlo->refcnt > 1)	/* we needed one fd for the ioctl */
		return -EBUSY;
	if(filp==NULL) return -EINVAL;
	if(hlo->hlo_thread) { kthread_stop(hlo->hlo_thread); hlo->hlo_thread=NULL; }
	if(filp!=initial_file)
		fput(filp);
	else
	{
		filp_close(initial_file,0);
		initial_file=NULL;
	}
	hlo->backing_file  = NULL;
	hlo->backing_inode = NULL;
	if(hlo->underlying_filename) { kfree(hlo->underlying_filename); hlo->underlying_filename=NULL; }
	if(hlo->block_ptrs) { hbloop_free(hlo->block_ptrs, hlo->head.num_blocks+1); hlo->block_ptrs = NULL; }
	if(hlo->preload_cache)
	{
		int i;
		for(i=0; i < hlo->preload_size; i++)
			hbloop_free(hlo->preload_cache[i], hlo->head.block_size);
		hbloop_free(hlo->preload_cache, hlo->preload_array_size * sizeof(char *));
		hlo->preload_cache = NULL;
		hlo->preload_size = hlo->preload_array_size = 0;
	}
	if (hlo->buffered_blocknum)
	{
		hbloop_free(hlo->buffered_blocknum, sizeof(int) * hlo->num_buffered_blocks); hlo->buffered_blocknum = NULL;
	}
	if (hlo->buffer)
	{
		int i;
		for(i=0; i<hlo->num_buffered_blocks; i++) { if(hlo->buffer[i]) hbloop_free(hlo->buffer[i], hlo->head.block_size); }
		hbloop_free(hlo->buffer, sizeof(char*) * hlo->num_buffered_blocks); hlo->buffer = NULL;
	}
	if(hlo->compressed_buffer) { hbloop_free(hlo->compressed_buffer, hlo->largest_block); hlo->compressed_buffer = NULL; }
	if(bdev) invalidate_bdev(bdev);
	if(hlo->hlo_disk) set_capacity(hlo->hlo_disk, 0);
	return 0;
}



/* Copied from loop.c, stripped down to the really necessary */
static int hbloop_set_status(struct hbloop_device *hlo,
		const struct loop_info64 *info)
{
	if (!hlo->backing_file) return -ENXIO;
	if(hlo->underlying_filename) kfree(hlo->underlying_filename);
	hlo->underlying_filename = kstrdup(info->lo_file_name, GFP_KERNEL);
	return 0;
}

static int hbloop_get_status(struct hbloop_device *hlo,
		struct loop_info64 *info)
{
	struct file *file = hlo->backing_file;
	struct kstat stat;
	int err;
	if (!file) return -ENXIO;
	err = vfs_getattr(&file->f_path, &stat, STATX_BASIC_STATS, AT_STATX_SYNC_AS_STAT);
	if (err) return err;
	memset(info, 0, sizeof(*info));
	info->lo_number  = hlo->hlo_number;
	info->lo_device  = huge_encode_dev(stat.dev);
	info->lo_inode   = stat.ino;
	info->lo_rdevice = huge_encode_dev(hlo->isblkdev ? stat.rdev : stat.dev);
	info->lo_offset  = 0;
	info->lo_sizelimit = 0;
	info->lo_flags   = 0;
	strncpy(info->lo_file_name, hlo->underlying_filename, LO_NAME_SIZE);
	info->lo_file_name[LO_NAME_SIZE-1]=0;
	return 0;
}




static void hbloop_info64_from_old(const struct loop_info *info,
		struct loop_info64 *info64)
{
	memset(info64, 0, sizeof(*info64));
	info64->lo_number = info->lo_number;
	info64->lo_device = info->lo_device;
	info64->lo_inode = info->lo_inode;
	info64->lo_rdevice = info->lo_rdevice;
	info64->lo_offset = info->lo_offset;
	info64->lo_sizelimit = 0;
	info64->lo_flags = info->lo_flags;
	info64->lo_init[0] = info->lo_init[0];
	info64->lo_init[1] = info->lo_init[1];
	memcpy(info64->lo_file_name, info->lo_name, LO_NAME_SIZE);
}

static int hbloop_info64_to_old(const struct loop_info64 *info64,
		struct loop_info *info)
{
	memset(info, 0, sizeof(*info));
	info->lo_number = info64->lo_number;
	info->lo_device = info64->lo_device;
	info->lo_inode = info64->lo_inode;
	info->lo_rdevice = info64->lo_rdevice;
	info->lo_offset = info64->lo_offset;
	info->lo_flags = info64->lo_flags;
	info->lo_init[0] = info64->lo_init[0];
	info->lo_init[1] = info64->lo_init[1];
	memcpy(info->lo_name, info64->lo_file_name, LO_NAME_SIZE);
	return 0;
}


static int hbloop_set_status_old(struct hbloop_device *hlo,
		const struct loop_info __user *arg)
{
	struct loop_info info;
	struct loop_info64 info64;

	if (copy_from_user(&info, arg, sizeof (struct loop_info))) return -EFAULT;
	hbloop_info64_from_old(&info, &info64);
	return hbloop_set_status(hlo, &info64);
}

static int hbloop_set_status64(struct hbloop_device *hlo,
		const struct loop_info64 __user *arg)
{
	struct loop_info64 info64;
	if (copy_from_user(&info64, arg, sizeof (struct loop_info64)))
		return -EFAULT;
	return hbloop_set_status(hlo, &info64);
}

static int hbloop_get_status_old(struct hbloop_device *hlo,
		struct loop_info __user *arg)
{
	struct loop_info info;
	struct loop_info64 info64;
	int err = 0;

	if (!arg) err = -EINVAL;
	if (!err) err = hbloop_get_status(hlo, &info64);
	if (!err) err = hbloop_info64_to_old(&info64, &info);
	if (!err && copy_to_user(arg, &info, sizeof(info))) err = -EFAULT;
	return err;
}

static int hbloop_get_status64(struct hbloop_device *hlo,
		struct loop_info64 __user *arg)
{
	struct loop_info64 info64;
	int err = 0;
	if (!arg) err = -EINVAL;
	if (!err) err = hbloop_get_status(hlo, &info64);
	if (!err && copy_to_user(arg, &info64, sizeof(info64))) err = -EFAULT;
	return err;
}

static int hbloop_ioctl(struct block_device *bdev, fmode_t mode,
		unsigned int cmd, unsigned long arg)
{
	struct hbloop_device *hlo;
	int hbloop_num, err=0;
	if (!bdev) return -EINVAL;
	hbloop_num = MINOR(bdev->bd_dev);
	if (hbloop_num < 0 || hbloop_num > hbloop_count-1) return -ENODEV;
	hlo = hbloop_dev[hbloop_num];
	mutex_lock(&hlo->hlo_ctl_mutex);
	switch (cmd)
	{ 
		case LOOP_SET_FD_MFILE:
			err = hbloop_set_fd_mfile(hlo, mode, bdev, (struct loop_mfile_fds __user *)arg);
			break;
		case LOOP_CLR_FD_MFILE:
			err = hbloop_clr_fd_mfile(hlo);
			if (!err)
				goto out_unlocked;
			break;
		case LOOP_SET_STATUS64_MFILE:
			err = -EPERM;
			if ((mode & FMODE_WRITE) || capable(CAP_SYS_ADMIN))
				err = loop_set_status64_mfile(hlo,
					(struct loop_info64 __user *) arg);
			break;
		case LOOP_GET_STATUS64_MFILE:
			err = loop_get_status64_mfile(hlo, (struct loop_info64 __user *) arg);
			/* loop_get_status() unlocks lo_ctl_mutex */
			goto out_unlocked;
		case HBLOOP_SUSPEND:
			err = hlo_suspend_fd(hbloop_num);
			break;
		default:
			err = -EINVAL;
	}
	mutex_unlock(&hlo->hlo_ctl_mutex);

out_unlocked:
	return err;
}


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
	memset(hlo, 0, sizeof(struct hbloop_device));
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
	if(file) /* global file name for first hbloop-Device is a module option string. */
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
					"%s: Unable to get file %s for hbloop device, error %d\n",
					hbloop_name, file, error);
			goto init_out_dealloc;
		}
	}
#endif 
	return 0;
init_out_dealloc:
	while (hbloop_count>0) hbloop_dealloc(--hbloop_count);
	unregister_blkdev(hbloop_major, hbloop_name);
init_out_hbloop_free:
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
		hbloop_dealloc(hbloop_count);
	}
	printk("%s: unloaded.\n", hbloop_name);
}

/* The hbloop init and exit function registration (especially needed for Kernel 2.6) */
module_init(hbloop_init);
module_exit(hbloop_exit);

#include <linux/vermagic.h>
#include <linux/compiler.h>

MODULE_INFO(vermagic, VERMAGIC_STRING);
