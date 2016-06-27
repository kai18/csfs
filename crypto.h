/*
 * crypto.h
 *
 *  Created on: Aug 24, 2015
 *      Author: kaustubh
 */

#ifndef CRYPTO_H_
#define CRYPTO_H_

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#define CYPHER_BLOCK_SIZE 16;

int random_gen(unsigned char*);
void handleerrors(void);
int csfs_encrypt(unsigned char*, int, unsigned char*, unsigned char*, unsigned char*);
int csfs_decrypt(unsigned char*, int, unsigned char*, unsigned char*, unsigned char*);


#endif /* CRYPTO_H_ */
