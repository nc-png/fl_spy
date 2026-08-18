/* fl_spy — glftpd-compatible ONLINE shared-memory layout. */
#ifndef FL_SPY_ONLINE_H
#define FL_SPY_ONLINE_H

#include <stdint.h>

#define FL_SHM_DEFAULT_KEY 0x0000DEAD

#pragma pack(push, 4)
typedef struct {
    int32_t tv_sec;
    int32_t tv_usec;
} shm_timeval32_t;

struct ONLINE {
    char            tagline[64];
    char            username[24];
    char            status[256];    /* "RETR /path", "STOR /path", "IDLE", ... */
    int16_t         ssl_flag;       /* 0 none, 1 control, 2 control+data */
    char            host[256];      /* "ident@ip" */
    char            currentdir[256];/* chroot-relative; file path during a transfer */
    int32_t         groupid;
    int32_t         login_time;     /* time(2) seconds since epoch */
    shm_timeval32_t tstart;         /* current transfer start */
    shm_timeval32_t txfer;          /* time of last successful transfer loop */
    uint64_t        bytes_xfer;     /* bytes so far in the current transfer */
    uint64_t        bytes_txfer;    /* bytes in the last loop */
    int32_t         procid;         /* transfer thread TID while transferring,
                                       daemon-internal conn id otherwise */
};
#pragma pack(pop)

#endif
