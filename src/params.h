/*

*/

#ifndef _PARAMS_H_
#define _PARAMS_H_


#define FUSE_USE_VERSION 26


#define _XOPEN_SOURCE 500

// maintain csfs state in here
#include <limits.h>
#include <stdio.h>
struct csfs_state {
    FILE *logfile;
    char *rootdir;
};
#define csfs_DATA ((struct csfs_state *) fuse_get_context()->private_data)

#endif
