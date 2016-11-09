/*
 * test.c
 *
 *  Created on: Sep 12, 2015
 *      Author: kaustubh
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
//#include <fuse.h>
#include <gcrypt.h>
#include <libtar.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ulockmgr.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#define ALGO GCRY_CIPHER_AES128
#define ALGO_MODE GCRY_CIPHER_MODE_CBC
csfs_encrypt(char *plain, char *out, char *enc_key, int len)
{
	gcry_cipher_hd_t  hd;
	gcry_error_t      err = 0;
	int               keylen;

	keylen = gcry_cipher_get_algo_keylen(ALGO);
	if (!keylen)
		perror("Wrong keylen");
	//if (keylen < MIN_KEY_LEN || keylen > 32)
		//perror("Wrong keylen");

	err = gcry_cipher_open(&hd, ALGO, ALGO_MODE, GCRY_CIPHER_SECURE);
	if (err)
		perror("Eror ini");

	err = gcry_cipher_setkey(hd, enc_key, keylen);
	if (err) {
		gcry_cipher_close(hd);
		perror("error init1");
	}

	err = gcry_cipher_encrypt(hd, out, len, plain, len);
	if (err) {
		gcry_cipher_close(hd);
		perror("error enrypting");
	}
	printf("%s",out);

	gcry_cipher_close(hd);
}

int main()
{
	char *c;
	csfs_encrypt("abcdefghuldjeothg",&c,"ab32k5j3,",16);

	return 0;
}

