
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

	/* An array of hbloop_ptr flags/offset for compressed blocks within the file */
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




