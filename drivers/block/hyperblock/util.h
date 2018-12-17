#ifndef UTIL_H
#define UTIL_H

#include <linux/err.h>    
#include <linux/printk.h> 

#define PRINT_INFO(fmt, ...)                                     \
        do { if ((HBDEBUG)) \
        printk(KERN_INFO fmt, ## __VA_ARGS__);} while (0)

#define PRINT_ERROR(fmt, ...)                                          \
        do { if ((HBDEBUG)) \
        printk(KERN_ERR fmt, ## __VA_ARGS__);} while (0)
#define ASSERT(exp)                                             \
        BUG_ON(exp)       
#endif

