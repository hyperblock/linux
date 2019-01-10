#ifndef UTIL_H
#define UTIL_H

#include <linux/err.h>    
#include <linux/printk.h> 
#define HBDEBUG 1
#define PRINT_INFO(fmt, ...)                                     \
        do { if ((HBDEBUG)) \
        printk(KERN_INFO fmt, ## __VA_ARGS__);} while (0)

//#define H_DBG_G(fmt, args...) printk(KERN_INFO, "\033[1;32m  TRC_PG(%s:%d):\t\033[0m" fmt, __func__, __LINE__, ## args)
//#define H_DBG_R(fmt, args...) printk(KERN_ERR, "\033[1;31m  TRC_PG(%s:%d):\t\033[0m" fmt, __func__, __LINE__, ## args)

#define PRINT_ERROR(fmt, ...)                                          \
        do { if ((HBDEBUG)) \
        printk(KERN_ERR fmt, ## __VA_ARGS__);} while (0)
#define ASSERT(exp)                                             \
        BUG_ON(!(exp))       
#endif

