#ifndef _AES_GCM_H_
#define _AES_GCM_H_

void handleErrors(void);
int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *tag);

#endif
