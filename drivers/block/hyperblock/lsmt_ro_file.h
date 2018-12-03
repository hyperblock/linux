#ifndef __LSMT_RO_H__
#define __LSMT_RO_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#define PRINT_INFO(fmt, ...)                                     \
        printf("\033[33m|INFO |\033[0mline: %d|%s: " fmt "\n", \
               __LINE__, __FUNCTION__, __VA_ARGS__)

#define PRINT_ERROR(fmt, ...)                                          \
        fprintf(stderr, "\033[31m|ERROR|\033[0m%s:%d|%s: " fmt "\n", \
                __FILE__, __LINE__, __FUNCTION__, __VA_ARGS__)

#define ALIGNED_MEM(name, size, alignment)  \
        char __buf##name[(size) + (alignment)]; \
        char *name = (char *)(((uint64_t)(__buf##name + (alignment) - 1)) & \
                        ~((uint64_t)(alignment) - 1));

#define REVERSE_LIST(type, begin, back) { type *l = (begin); type *r = (back);\
        while (l<r){ type tmp = *l; *l = *r; *r = tmp; l++; r--; }} \

#define TYPE_SEGMENT         0
#define TYPE_SEGMENT_MAPPING 1
#define TYPE_FILDES          2   
#define TYPE_LSMT_RO_INDEX   3

struct lsmt_ro_file {
        struct lsmt_ro_index *m_index;
        uint64_t m_vsize;
        bool m_ownership;       
        size_t m_files_count;
        size_t MAX_IO_SIZE;
        int m_files[0];
};

int set_max_io_size(struct lsmt_ro_file *file, size_t size);
size_t get_max_io_size(const struct lsmt_ro_file *file );

// open a lsmt layer
struct lsmt_ro_file* open_file(int fd, bool ownership);

// open multi LSMT layers
struct lsmt_ro_file *open_files(int *files, size_t n, bool ownership);

size_t lsmt_pread(struct lsmt_ro_file *file, 
                char *buf, size_t count, uint64_t offset);

        
#endif