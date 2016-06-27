/*
 *Clean Slate Crypto Module
 *
 *Author: Kaustubh
*/

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>


/*int random_gen(unsigned char *random_data) {//generate random data from /dev/urandom
	int fd = open("/dev/urandom", O_RDONLY);
	int result = arc4random_buf(random_data,sizeof(random_data));
	if (result<0) {
		close(fd);
		return 1;
	} else {
		close(fd);
		return 0;
	}
}*/

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int csfs_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();


  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
    handleErrors();

  if(plaintext_len > 16)
  {
	  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		  handleErrors();
  	  ciphertext_len = len;	int fd = open("/dev/urandom", O_RDONLY);

  }

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  printf("%d\n",ciphertext_len);
  return ciphertext_len;
}


int csfs_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();


  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
    handleErrors();

  if(ciphertext_len > 16)
  {
	  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		  handleErrors();
  	  plaintext_len = len;

  }
  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);
  printf("%d\n",plaintext_len);

  return plaintext_len;
}

