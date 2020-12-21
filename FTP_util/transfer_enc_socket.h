#ifndef _TRANSFER_SOCKET_H_
#define _TRANSFER_SOCKET_H_

#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void error_handling(char *msg);
int getCode(char *message);
void free_file(char *file);

void set_rsa_pubkey(int *sockfd, unsigned char *key, unsigned char *iv);
void set_rsa_key(int *sockfd, unsigned char *key, unsigned char *iv, RSA *rsa_pubkey, RSA *rsa_privkey);

void send_msg(int *sockfd, unsigned char *message, unsigned char *additional, unsigned char *key, unsigned char *iv);
void received_msg(int *sockfd, unsigned char *buf_out, unsigned char *additional, unsigned char *key, unsigned char *iv);
int received_file(int *sockfd, char* oFilename, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv);
int send_file(int *sockfd, char *iFilename, unsigned char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv);

#endif
