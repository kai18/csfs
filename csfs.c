/*
 * csfs.c
 *      Author: Kaustubh
 */

/*
 Clean Slate File System

 Compiler Flags: gcc -Wall -lcrypto `pkg-config fuse --cflags --libs` `libgcrypt-config --cflags --libs` -o csfs csfs.c log.c crypto.c
 */

#include "params.h"
#include "csfs.h"
#include "crypto.h"

#ifdef HAVE_SYS_XATTR_H
#include <sys/xattr.h>
#endif

#include "log.h"
unsigned char *key = (unsigned char *) "01234567890123456789012345678901";

/* A 128 bit IV */
unsigned char *iv = (unsigned char *) "01234567890123456";
// Report errors to logfile and give -errno to caller
static int csfs_error(char *str) {
	int ret = -errno;

	log_msg("    ERROR %s: %s\n", str, strerror(errno));

	return ret;
}

// Check whether the given user is permitted to perform the given operation on the given

static void csfs_fullpath(char fpath[PATH_MAX], const char *path) {
	strcpy(fpath, csfs_DATA->rootdir);
	strncat(fpath, path, PATH_MAX); // ridiculously long paths will
	// break here

	log_msg(
			"    csfs_fullpath:  rootdir = \"%s\", path = \"%s\", fpath = \"%s\"\n",
			csfs_DATA->rootdir, path, fpath);
}

int csfs_getattr(const char *path, struct stat *statbuf) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_getattr(path=\"%s\", statbuf=0x%08x)\n", path, statbuf);
	csfs_fullpath(fpath, path);

	retstat = lstat(fpath, statbuf);
	if (retstat != 0)
		retstat = csfs_error("csfs_getattr lstat");

	log_stat(statbuf);

	return retstat;
}

int csfs_readlink(const char *path, char *link, size_t size) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("csfs_readlink(path=\"%s\", link=\"%s\", size=%d)\n", path, link,
			size);
	csfs_fullpath(fpath, path);

	retstat = readlink(fpath, link, size - 1);
	if (retstat < 0)
		retstat = csfs_error("csfs_readlink readlink");
	else {
		link[retstat] = '\0';
		retstat = 0;
	}

	return retstat;
}

int csfs_mknod(const char *path, mode_t mode, dev_t dev) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_mknod(path=\"%s\", mode=0%3o, dev=%lld)\n", path, mode,
			dev);
	csfs_fullpath(fpath, path);

	// On Linux this could just be 'mknod(path, mode, rdev)' but this
	//  is more portable
	if (S_ISREG(mode)) {
		retstat = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (retstat < 0)
			retstat = csfs_error("csfs_mknod open");
		else {
			retstat = close(retstat);
			if (retstat < 0)
				retstat = csfs_error("csfs_mknod close");
		}
	} else if (S_ISFIFO(mode)) {
		retstat = mkfifo(fpath, mode);
		if (retstat < 0)
			retstat = csfs_error("csfs_mknod mkfifo");
	} else {
		retstat = mknod(fpath, mode, dev);
		if (retstat < 0)
			retstat = csfs_error("csfs_mknod mknod");
	}

	return retstat;
}

/** Create a directory */
int csfs_mkdir(const char *path, mode_t mode) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_mkdir(path=\"%s\", mode=0%3o)\n", path, mode);
	csfs_fullpath(fpath, path);

	retstat = mkdir(fpath, mode);
	if (retstat < 0)
		retstat = csfs_error("csfs_mkdir mkdir");

	return retstat;
}

/** Remove a file */
int csfs_unlink(const char *path) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("csfs_unlink(path=\"%s\")\n", path);
	csfs_fullpath(fpath, path);

	retstat = unlink(fpath);
	if (retstat < 0)
		retstat = csfs_error("csfs_unlink unlink");

	return retstat;
}

/** Remove a directory */
int csfs_rmdir(const char *path) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("csfs_rmdir(path=\"%s\")\n", path);
	csfs_fullpath(fpath, path);

	retstat = rmdir(fpath);
	if (retstat < 0)
		retstat = csfs_error("csfs_rmdir rmdir");

	return retstat;
}

/** Create a symbolic link */

int csfs_symlink(const char *path, const char *link) {
	int retstat = 0;
	char flink[PATH_MAX];

	log_msg("\ncsfs_symlink(path=\"%s\", link=\"%s\")\n", path, link);
	csfs_fullpath(flink, link);

	retstat = symlink(path, flink);
	if (retstat < 0)
		retstat = csfs_error("csfs_symlink symlink");

	return retstat;
}

/** Rename a file */
int csfs_rename(const char *path, const char *newpath) {
	int retstat = 0;
	char fpath[PATH_MAX];
	char fnewpath[PATH_MAX];

	log_msg("\ncsfs_rename(fpath=\"%s\", newpath=\"%s\")\n", path, newpath);
	csfs_fullpath(fpath, path);
	csfs_fullpath(fnewpath, newpath);

	retstat = rename(fpath, fnewpath);
	if (retstat < 0)
		retstat = csfs_error("csfs_rename rename");

	return retstat;
}

/** Create a hard link to a file */
int csfs_link(const char *path, const char *newpath) {
	int retstat = 0;
	char fpath[PATH_MAX], fnewpath[PATH_MAX];

	log_msg("\ncsfs_link(path=\"%s\", newpath=\"%s\")\n", path, newpath);
	csfs_fullpath(fpath, path);
	csfs_fullpath(fnewpath, newpath);

	retstat = link(fpath, fnewpath);
	if (retstat < 0)
		retstat = csfs_error("csfs_link link");

	return retstat;
}

/** Change the permission bits of a file */
int csfs_chmod(const char *path, mode_t mode) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_chmod(fpath=\"%s\", mode=0%03o)\n", path, mode);
	csfs_fullpath(fpath, path);

	retstat = chmod(fpath, mode);
	if (retstat < 0)
		retstat = csfs_error("csfs_chmod chmod");

	return retstat;
}

/** Change the owner and group of a file */
int csfs_chown(const char *path, uid_t uid, gid_t gid)

{
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_chown(path=\"%s\", uid=%d, gid=%d)\n", path, uid, gid);
	csfs_fullpath(fpath, path);

	retstat = chown(fpath, uid, gid);
	if (retstat < 0)
		retstat = csfs_error("csfs_chown chown");

	return retstat;
}

/** Change the size of a file */
int csfs_truncate(const char *path, off_t newsize) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_truncate(path=\"%s\", newsize=%lld)\n", path, newsize);
	csfs_fullpath(fpath, path);

	retstat = truncate(fpath, newsize);
	if (retstat < 0)
		csfs_error("csfs_truncate truncate");

	return retstat;
}

/** Change the access and/or modification times of a file */
int csfs_utime(const char *path, struct utimbuf *ubuf) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_utime(path=\"%s\", ubuf=0x%08x)\n", path, ubuf);
	csfs_fullpath(fpath, path);

	retstat = utime(fpath, ubuf);
	if (retstat < 0)
		retstat = csfs_error("csfs_utime utime");

	return retstat;
}

/** File open operation
 */
int csfs_open(const char *path, struct fuse_file_info *fi) {
	int retstat = 0;
	int fd;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_open(path\"%s\", fi=0x%08x)\n", path, fi);
	csfs_fullpath(fpath, path);
	//fetch_key();
	fd = open(fpath, fi->flags);
	if (fd < 0)
		retstat = csfs_error("csfs_open open");

	fi->fh = fd;
	log_fi(fi);

	return retstat;
}

//Read data from an open file

static size_t get_size(int fd)
{
	struct stat buf;
	fstat(fd, &buf);
	return buf.st_size;
}
/* We read data in blocks and write data in blocks. So we need to find
 * block numbers to identify which block the data belongs to.
 *
 * */
int csfs_read(const char *path, unsigned char *buf, size_t size, off_t offset,
			  struct fuse_file_info *fi) {

	int retstat = 0, p_len = -1;
	size_t pending = size;
	off_t block_off,block_no, pending_blocks;
	unsigned char *p_text;
	unsigned char *c_text;
	size_t file_size = get_size(fi->fh);

	block_no = offset/BLOCK_SIZE;
	block_off = (block_no*BLOCK_SIZE);

	if(size % BLOCK_SIZE == 0)
		pending_blocks = size/BLOCK_SIZE;
	else
		pending_blocks = (size/BLOCK_SIZE)+1;

	p_text = (unsigned char*)calloc(pending_blocks*BLOCK_SIZE, sizeof(unsigned char));
	c_text = (unsigned char*)malloc(BLOCK_SIZE*sizeof(unsigned char));

	log_msg(
			"\ncsfs_read(path=\"%s\", buf=0x%08x, size=%d, offset=%lld, fi=0x%08x)\n",
			path, buf, size, offset, fi);
	// no need to get fpath on this one, since I work from fi->fh not the path
	log_fi(fi);
	pread(fi->fh, buf, size, offset);
	while(pending_blocks--)
	{
		retstat = pread(fi->fh, c_text, BLOCK_SIZE, block_off);
		p_len += csfs_decrypt(c_text, retstat, key, iv, p_text+((p_len < 0)?0:p_len));
		block_off +=BLOCK_SIZE;
	}

	memcpy(buf, p_text, size);
	return size;

/*	fprintf(stderr, "plaint text length is %d\n buf length is %d", p_len,
					strlen(buf));
	fprintf(stderr, "retstat is %d and size is %lu", retstat, size);*/

}

void fetch_key()
{
	sleep(2*.397);
}
/** Write data to an open file
 *
 * Write should return exactly the number of bytes requested
 * except on error.  An exception to this is when the 'direct_io'
 * mount option is specified (see read operation).
 */

int csfs_write(const char *path, unsigned char *buf, size_t size,
			   off_t offset, struct fuse_file_info *fi) {

	int retstat, c_len, chunk_off=0;
	unsigned char *ebuf = (unsigned char*)malloc(
			BLOCK_SIZE*sizeof(unsigned char));
	off_t off = offset;
	size_t remaining_bytes = size, file_size;
	file_size = get_size(fi->fh);
	fprintf(stderr, "SIZE = %d ", remaining_bytes);

	while(remaining_bytes > 0)
	{
		fprintf(stderr, "SiZE = %d ", remaining_bytes);
		if(remaining_bytes <= BLOCK_SIZE)
		{
			fprintf(stderr, "SIzE = %d ", remaining_bytes);
			c_len = csfs_encrypt(buf+chunk_off, remaining_bytes, key, iv, ebuf);
			retstat += pwrite(fi->fh, ebuf, size, offset);
			remaining_bytes -= BLOCK_SIZE;
			off = off + BLOCK_SIZE;
			chunk_off += BLOCK_SIZE;
			fprintf(stderr, "SIzE = %d ", remaining_bytes);
			free(ebuf);
			return size;
		}
		else if(remaining_bytes > BLOCK_SIZE)
		{
			fprintf(stderr, "SIZe = %d ", remaining_bytes);
			while(remaining_bytes >= BLOCK_SIZE)
			{
				c_len = csfs_encrypt(buf+chunk_off, BLOCK_SIZE, key, iv, ebuf);
				retstat += pwrite(fi->fh, ebuf, c_len, off);
				remaining_bytes -= BLOCK_SIZE;
				off = off+BLOCK_SIZE;
				chunk_off += BLOCK_SIZE;
				fprintf(stderr, "SIZe = %d ", remaining_bytes);
			}
		}
	}
	log_msg(
			"\ncsfs_write(path=\"%s\", buf=0x%08x, size=%d,"
					" offset=%lld, fi=0x%08x)\n",
			path, buf, size, offset, fi);
	// no need to get path on this one, since I work from fi->fh not the path
	log_fi(fi);


	if (retstat < 0)
		retstat = csfs_error("csfs_write pwrite");
	free(ebuf);
	return size;
}

/*struct stat get_Size(int fd)
{
	struct stat buf;
	fstat(fd, &buf);
	return buf.st_size;
}*/

/** Get file system statistics

 */
int csfs_statfs(const char *path, struct statvfs *statv) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_statfs(path=\"%s\", statv=0x%08x)\n", path, statv);
	csfs_fullpath(fpath, path);

	// get stats for underlying filesystem
	retstat = statvfs(fpath, statv);
	if (retstat < 0)
		retstat = csfs_error("csfs_statfs statvfs");

	log_statvfs(statv);

	return retstat;
}

/** Possibly flush cached data
 */
int csfs_flush(const char *path, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_flush(path=\"%s\", fi=0x%08x)\n", path, fi);
	// no need to get fpath on this one, since I work from fi->fh not the path
	log_fi(fi);

	return retstat;
}

/** Release an open file
 */
int csfs_release(const char *path, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_release(path=\"%s\", fi=0x%08x)\n", path, fi);
	log_fi(fi);

	// We need to close the file.  Had we allocated any resources
	// (buffers etc) we'd need to free them here as well.
	retstat = close(fi->fh);

	return retstat;
}

/** Synchronize file contents
 */
int csfs_fsync(const char *path, int datasync, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_fsync(path=\"%s\", datasync=%d, fi=0x%08x)\n", path,
			datasync, fi);
	log_fi(fi);

	// some unix-like systems (notably freebsd) don't have a datasync call
#ifdef HAVE_FDATASYNC
	if (datasync)
	retstat = fdatasync(fi->fh);
	else
#endif
	retstat = fsync(fi->fh);

	if (retstat < 0)
		csfs_error("csfs_fsync fsync");

	return retstat;
}

/** Set extended attributes */
int csfs_setxattr(const char *path, const char *name, const char *value,
				  size_t size, int flags) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg(
			"\ncsfs_setxattr(path=\"%s\", name=\"%s\", value=\"%s\", size=%d, flags=0x%08x)\n",
			path, name, value, size, flags);
	csfs_fullpath(fpath, path);

	retstat = lsetxattr(fpath, name, value, size, flags);
	if (retstat < 0)
		retstat = csfs_error("csfs_setxattr lsetxattr");

	return retstat;
}

/** Get extended attributes */
int csfs_getxattr(const char *path, const char *name, char *value, size_t size) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg(
			"\ncsfs_getxattr(path = \"%s\", name = \"%s\", value = 0x%08x, size = %d)\n",
			path, name, value, size);
	csfs_fullpath(fpath, path);

	retstat = lgetxattr(fpath, name, value, size);
	if (retstat < 0)
		retstat = csfs_error("csfs_getxattr lgetxattr");
	else
		log_msg("    value = \"%s\"\n", value);

	return retstat;
}

/** List extended attributes */
int csfs_listxattr(const char *path, char *list, size_t size) {
	int retstat = 0;
	char fpath[PATH_MAX];
	char *ptr;

	log_msg("csfs_listxattr(path=\"%s\", list=0x%08x, size=%d)\n", path, list,
			size);
	csfs_fullpath(fpath, path);

	retstat = llistxattr(fpath, list, size);
	if (retstat < 0)
		retstat = csfs_error("csfs_listxattr llistxattr");

	log_msg("    returned attributes (length %d):\n", retstat);
	for (ptr = list; ptr < list + retstat; ptr += strlen(ptr) + 1)
		log_msg("    \"%s\"\n", ptr);

	return retstat;
}

/** Remove extended attributes */
int csfs_removexattr(const char *path, const char *name) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_removexattr(path=\"%s\", name=\"%s\")\n", path, name);
	csfs_fullpath(fpath, path);

	retstat = lremovexattr(fpath, name);
	if (retstat < 0)
		retstat = csfs_error("csfs_removexattr lrmovexattr");

	return retstat;
}

/** Open directory
 *
 * This method should check if the open operation is permitted for
 * this  directory
 *
 * Introduced in version 2.3
 */
int csfs_opendir(const char *path, struct fuse_file_info *fi) {
	DIR *dp;
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_opendir(path=\"%s\", fi=0x%08x)\n", path, fi);
	csfs_fullpath(fpath, path);

	dp = opendir(fpath);
	if (dp == NULL)
		retstat = csfs_error("csfs_opendir opendir");

	fi->fh = (intptr_t) dp;

	log_fi(fi);

	return retstat;
}

/** Read directory
 */
int csfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
				 off_t offset, struct fuse_file_info *fi) {
	int retstat = 0;
	DIR *dp;
	struct dirent *de;

	log_msg(
			"\ncsfs_readdir(path=\"%s\", buf=0x%08x, filler=0x%08x, offset=%lld, fi=0x%08x)\n",
			path, buf, filler, offset, fi);
	dp = (DIR *) (uintptr_t) fi->fh;

	de = readdir(dp);
	if (de == 0) {
		retstat = csfs_error("csfs_readdir readdir");
		return retstat;
	}

	do {
		log_msg("calling filler with name %s\n", de->d_name);
		if (filler(buf, de->d_name, NULL, 0) != 0) {
			log_msg("    ERROR csfs_readdir filler:  buffer full");
			return -ENOMEM;
		}
	} while ((de = readdir(dp)) != NULL);

	log_fi(fi);

	return retstat;
}

/** Release directory
 */
int csfs_releasedir(const char *path, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_releasedir(path=\"%s\", fi=0x%08x)\n", path, fi);
	log_fi(fi);

	closedir((DIR *) (uintptr_t) fi->fh);

	return retstat;
}

/** Synchronize directory contents
 */
int csfs_fsyncdir(const char *path, int datasync, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_fsyncdir(path=\"%s\", datasync=%d, fi=0x%08x)\n", path,
			datasync, fi);
	log_fi(fi);

	return retstat;
}

/**
 * Initialize filesystem
 *
 * The return value will passed in the private_data field of
 * fuse_context to all file operations and as a parameter to the
 * destroy() method.
 */
// Undocumented but extraordinarily useful fact:  the fuse_context is
// set up before this function is called, and
// fuse_get_context()->private_data returns the user_data passed to fuse_main().
void *csfs_init(struct fuse_conn_info *conn) {
	log_msg("\ncsfs_init()\n");

	log_conn(conn);
	log_fuse_context(fuse_get_context());

	return csfs_DATA;
}

/**
 * Clean up filesystem
 *
 * Called on filesystem exit.
 */
void csfs_destroy(void *userdata) {
	log_msg("\ncsfs_destroy(userdata=0x%08x)\n", userdata);
}

/**
 * Check file access permissions
 */
int csfs_access(const char *path, int mask) {
	int retstat = 0;
	char fpath[PATH_MAX];

	log_msg("\ncsfs_access(path=\"%s\", mask=0%o)\n", path, mask);
	csfs_fullpath(fpath, path);

	retstat = access(fpath, mask);

	if (retstat < 0)
		retstat = csfs_error("csfs_access access");

	return retstat;
}

/**
 * Create and open a file
 */
int csfs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
	int retstat = 0;
	char fpath[PATH_MAX];
	int fd;

	log_msg("\ncsfs_create(path=\"%s\", mode=0%03o, fi=0x%08x)\n", path, mode,
			fi);
	csfs_fullpath(fpath, path);

	fd = creat(fpath, mode);
	//csfs_setxattr(path, CSFS_ID, csfs_id++, sizeof(csfs_id),XATTRCREATE);
	if (fd < 0)
		retstat = csfs_error("csfs_create creat");

	fi->fh = fd;

	log_fi(fi);

	return retstat;
}

/**
 * Change the size of an open file
 */
int csfs_ftruncate(const char *path, off_t offset, struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_ftruncate(path=\"%s\", offset=%lld, fi=0x%08x)\n", path,
			offset, fi);
	log_fi(fi);

	retstat = ftruncate(fi->fh, offset);
	if (retstat < 0)
		retstat = csfs_error("csfs_ftruncate ftruncate");

	return retstat;
}

/**
 * Get attributes from an open file
 */
int csfs_fgetattr(const char *path, struct stat *statbuf,
				  struct fuse_file_info *fi) {
	int retstat = 0;

	log_msg("\ncsfs_fgetattr(path=\"%s\", statbuf=0x%08x, fi=0x%08x)\n", path,
			statbuf, fi);
	log_fi(fi);

	if (!strcmp(path, "/"))
		return csfs_getattr(path, statbuf);

	retstat = fstat(fi->fh, statbuf);
	if (retstat < 0)
		retstat = csfs_error("csfs_fgetattr fstat");

	log_stat(statbuf);

	return retstat;
}

struct fuse_operations csfs_oper = { .getattr = csfs_getattr, .readlink =
csfs_readlink,
		// no .getdir -- that's deprecated
		.getdir = NULL, .mknod = csfs_mknod, .mkdir = csfs_mkdir, .unlink =
		csfs_unlink, .rmdir = csfs_rmdir, .symlink = csfs_symlink,
		.rename = csfs_rename, .link = csfs_link, .chmod = csfs_chmod, .chown =
		csfs_chown, .truncate = csfs_truncate, .utime = csfs_utime,
		.open = csfs_open, .read = csfs_read, .write = csfs_write,
		/** Just a placeholder, don't set */ // huh???
		.statfs = csfs_statfs, .flush = csfs_flush, .release = csfs_release,
		.fsync = csfs_fsync,

		.setxattr = csfs_setxattr, .getxattr = csfs_getxattr, .listxattr =
		csfs_listxattr, .removexattr = csfs_removexattr,

		.opendir = csfs_opendir, .readdir = csfs_readdir, .releasedir =
		csfs_releasedir, .fsyncdir = csfs_fsyncdir, .init = csfs_init,
		.destroy = csfs_destroy, .access = csfs_access, .create = csfs_create,
		.ftruncate = csfs_ftruncate, .fgetattr = csfs_fgetattr };

void csfs_usage() {
	fprintf(stderr,
			"usage:  csfs [FUSE and mount options] rootDir mountPoint\n");
	abort();
}

int main(int argc, char *argv[]) {
	int fuse_stat;
	struct csfs_state *csfs_data;
	//random_gen(&key);
	//random_gen(&iv);
	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr,
				"Running csfs as root opens unnacceptable security holes\n");
		return 1;
	}
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
	// Perform some sanity checking on the command line:  make sure
	// there are enough arguments, and that neither of the last two
	// start with a hyphen
	if ((argc < 3) || (argv[argc - 2][0] == '-') || (argv[argc - 1][0] == '-'))
		csfs_usage();

	csfs_data = malloc(sizeof(struct csfs_state));
	if (csfs_data == NULL) {
		perror("main calloc");
		abort();
	}

	// Pull the rootdir out of the argument list and save it in my
	// internal data
	csfs_data->rootdir = realpath(argv[argc - 2], NULL);
	argv[argc - 2] = argv[argc - 1];
	argv[argc - 1] = NULL;
	argc--;

	csfs_data->logfile = log_open();

	// turn over control to fuse
	//device pairing will occur here
	fprintf(stderr, "about to call fuse_main\n");
	fuse_stat = fuse_main(argc, argv, &csfs_oper, csfs_data);
	fprintf(stderr, "fuse_main returned %d\n", fuse_stat);
	EVP_cleanup();
	ERR_free_strings();

	return fuse_stat;
}
