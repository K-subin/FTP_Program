#ifndef _MSG_H_
#define _MSG_H_

#define STRSIZE	        20
#define BUFSIZE         512
#define AES_BLOCK_SIZE  16
#define AES_KEY_128     16
#define AES_IV_128      12
#define TAGSIZE         16
#define ADDSIZE         32

enum MSG_TYPE{
  PUBLIC_KEY,
  SECRET_KEY,
  PUBLIC_KEY_REQUEST,
  IV,
  ENCRYPTED_KEY,
  ENCRYPTED_MSG
};

typedef struct _APP_MSG_
{
  int type;
  unsigned char payload[BUFSIZE+AES_BLOCK_SIZE];
  int msg_len;
}APP_MSG;

#endif
