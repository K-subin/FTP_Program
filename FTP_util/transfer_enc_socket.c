#include "transfer_enc_socket.h"

#include "readnwrite.h"
#include "msg.h"
#include "aes_gcm.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

APP_MSG msg_in; // 상대방이 보낸 메세지 저장
APP_MSG msg_out; // 보낼 메시지 저장

void error_handling(char *msg){
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}

void free_file(char *file){
	// 할당 해제
	if(file != NULL){
		free(file);
		file = NULL;
	}
}

void set_rsa_pubkey(int *sockfd, unsigned char *key, unsigned char *iv)
{
	int n;
	unsigned char encrypted_key[BUFSIZE] = {0x00, };
	BIO *rpub = NULL;
	RSA *rsa_pubkey = NULL;

	RAND_poll();
	RAND_bytes(key, sizeof(key));

	// setup process
	// sending PUBLIC_KEY_REQUEST_msg
	memset(&msg_out, 0, sizeof(APP_MSG));
	msg_out.type = PUBLIC_KEY_REQUEST;
	msg_out.type = htonl(msg_out.type);

	n = writen(*sockfd, &msg_out, sizeof(APP_MSG));
	if(n == -1){
		error_handling("writen() error");
	}

	// received PUBLIC_KEY msg
	memset(&msg_in, 0, sizeof(APP_MSG));
	n = readn(*sockfd, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);

	if(n == -1){
		error_handling("readn() error");
	}
	else if(n == 0){
		error_handling("reading EOF");
	}

	if(msg_in.type != PUBLIC_KEY){
		error_handling("message error");
	}
	else{
		// 서버로부터의 공개키 메시지를 RSA 타입으로 변환
		rpub = BIO_new_mem_buf(msg_in.payload, -1); // payload 와 rpub 연결
		BIO_write(rpub, msg_in.payload, msg_in.msg_len); // rpub로 공개키 읽어들이기
		if(!PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL)){
			error_handling("PEM_read_bio_RSAPublicKey() error");
		}
	}

	// sending ENCRYPTED_KEY msg
	// 클라이언트는 랜덤하게 생성한 키를 서버의 공개키로 암호화하여 서버로 전송
	memset(&msg_out, 0, sizeof(APP_MSG));
	msg_out.type = ENCRYPTED_KEY;
	msg_out.type = htonl(msg_out.type);
	msg_out.msg_len = RSA_public_encrypt(sizeof(key), key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
	msg_out.msg_len = htonl(msg_out.msg_len);

	n = writen(*sockfd, &msg_out, sizeof(APP_MSG));
	if(n == -1){
		error_handling("writen() error");
	}
}

void set_rsa_key(int *sockfd, unsigned char *key, unsigned char *iv, RSA *rsa_pubkey, RSA *rsa_privkey)
{
	int publickey_len;
	int encryptedkey_len;
	int n;

	unsigned char buffer[BUFSIZE] = {0x00, };
	BIO *pub = NULL;

	// setup process
	// 클라이언트로부터의 공개키 요청 메시지를 수신
	memset(&msg_in, 0, sizeof(APP_MSG));
	n = readn(*sockfd, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);
	if(n == -1){
		error_handling("readn() error");
	}
	else if(n == 0){
		error_handling("reading EOF");
	}

	if(msg_in.type != PUBLIC_KEY_REQUEST){
		error_handling("message error");
	}
	else{
		// 곧개키를 메시지에 적재하여 클라이언트로 전송
		memset(&msg_out, 0, sizeof(APP_MSG));
		msg_out.type = PUBLIC_KEY;
		msg_out.type = htonl(msg_out.type);

		pub = BIO_new(BIO_s_mem());
		PEM_write_bio_RSAPublicKey(pub, rsa_pubkey); // publickey를 pub에 쓴다.
		publickey_len = BIO_pending(pub); // pub에 들어있는 데이터크기 알아내기

		BIO_read(pub, msg_out.payload, publickey_len);
		msg_out.msg_len = htonl(publickey_len);

		n = writen(*sockfd, &msg_out, sizeof(APP_MSG)); // 공개키 전송
		if(n == -1){
			error_handling("writen() error");
		}
	}

	memset(&msg_in, 0, sizeof(APP_MSG));
	n = readn(*sockfd, &msg_in, sizeof(APP_MSG));
	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);

	if(msg_in.type != ENCRYPTED_KEY){
		error_handling("message error");
	}
	else{
		encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
		memcpy(key, buffer, encryptedkey_len);
	}
}

void send_msg(int *sockfd, unsigned char *message, unsigned char *additional, unsigned char *key, unsigned char *iv)
{
	int len, n;
	int ciphertext_len;
	unsigned char tag[16] = {0x00, };

	// removing '\n' character
	len = strlen(message);
	if(message[len-1] == '\n')
		message[len-1] = '\0';
	if(strlen(message) == 0)
		return;

	memset(&msg_out, 0, sizeof(msg_out));
	msg_out.type = ENCRYPTED_MSG;
	msg_out.type = htonl(msg_out.type);

	ciphertext_len = gcm_encrypt(message, strlen((char*)message), additional, strlen((char*)additional), key, iv, msg_out.payload, tag);
	msg_out.msg_len = htonl(ciphertext_len);

	// sending the inputed message
	n = writen(*sockfd, &msg_out, sizeof(APP_MSG));
	if(n == -1){
		error_handling("writen() error");
		return;
	}
	n = writen(*sockfd, tag, 16);
	if(n == -1){
		error_handling("writen() error");
		return;
	}
}


void received_msg(int *sockfd, unsigned char *buf_out, unsigned char *additional, unsigned char *key, unsigned char *iv)
{
	int n;
	int plaintext_len;
	unsigned char tag[16] = {0x00, };

	n = readn(*sockfd, &msg_in, sizeof(APP_MSG));
	if(n == -1){
		error_handling("readn() error");
		return;
	}
	else if(n == 0){ // receiving EOF
		return;
	}

	n = readn(*sockfd, tag, 16);
	if(n == -1){
		error_handling("readn() error");
		return;
	}
	else if(n == 0){ // receiving EOF
		return;
	}

	msg_in.type = ntohl(msg_in.type);
	msg_in.msg_len = ntohl(msg_in.msg_len);

	switch (msg_in.type) {
		case ENCRYPTED_MSG:
			plaintext_len = gcm_decrypt(msg_in.payload, msg_in.msg_len, additional, strlen((char*)additional), key, iv, buf_out, tag);
			break;
		default:
			break;
	}

	if(plaintext_len >= 0){
		buf_out[plaintext_len] = '\0';
	}
	else{
		error_handling("tag error");
		return;
	}
}


int send_file(int *sockfd, char *iFilename, unsigned char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv)
{
	FILE* ifp = NULL;
  int plainfile_len;
	int cipherfile_len;
  unsigned char* plainfile = NULL;
  unsigned char* cipherfile = NULL;
	unsigned char tag[16] = {0x00, };
	int n;
	int intCode;

	char response_150[] = "150 file status ok.\r\n";
	char response_151[] = "151 file status not ok.\r\n";

	// 서버 파일 열기
  ifp = fopen(iFilename, "rb");
	if(ifp == NULL){
		printf("Input file does not exist.\n");
		send_msg(sockfd, response_151, additional, key, iv);
		return 151;
	}
	else{
		send_msg(sockfd, response_150, additional, key, iv);
	}

	received_msg(sockfd, plaintext, additional, key, iv);
	intCode = getCode(plaintext);
	if(intCode == 151){
		printf("Output file cannot be opened.\n");
		return 151;
	}

	// 서버 파일 사이즈 구하기
  fseek(ifp, 0, SEEK_END);
  plainfile_len = ftell(ifp);
  fseek(ifp, 0, SEEK_SET);

	// 할당
  plainfile = (unsigned char*)calloc(plainfile_len, sizeof(unsigned char));
  cipherfile = (unsigned char*)calloc(plainfile_len+AES_BLOCK_SIZE, sizeof(unsigned char));

	// 서버 파일 내용 읽기
  if(fread(plainfile, 1, plainfile_len, ifp) == 0){
		printf("fread() error\n");
		send_msg(sockfd, response_151, additional, key, iv);
		return 202;
  }
	else{
		send_msg(sockfd, response_150, additional, key, iv);
	}

	if(ifp != NULL){
    fclose(ifp);
  }

	// removing '\n' character
	if(plainfile[plainfile_len-1] == '\n')
		plainfile[plainfile_len-1] = '\0';

	// 서버 파일 내용 암호화
  cipherfile_len = gcm_encrypt(plainfile, plainfile_len, additional, strlen((char*)additional), key, iv, cipherfile, tag);

	// 암호화 파일 길이 보내기
	sprintf(plaintext, "%d", cipherfile_len);
	send_msg(sockfd, plaintext, additional, key, iv);

	// 암호화 파일 내용 보내기
	n = writen(*sockfd, cipherfile, cipherfile_len);
	if(n == -1){
		printf("Input cipherfile writen() error\n");
		return 202;
	}

	// tag 보내기
	n = writen(*sockfd, tag, 16);
	if(n == -1){
		printf("Input tag writen() error\n");
		return 202;
	}

	// 할당 해제
	free_file(plainfile);
	free_file(cipherfile);

	// Output tag 읽기 success
	received_msg(sockfd, plaintext, additional, key, iv);
	intCode = getCode(plaintext);
	if(intCode == 151){
		printf("Output tag error");
		return 151;
	}

	received_msg(sockfd, plaintext, additional, key, iv);
	intCode = getCode(plaintext);

	return intCode;
}


int received_file(int *sockfd, char* oFilename, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv)
{
  FILE* ofp = NULL;
  int plainfile_len;
	int cipherfile_len;
  unsigned char* plainfile = NULL;
  unsigned char* cipherfile = NULL;
	unsigned char tag[16] = {0x00, };
	int n;
	int intCode;

	char response_150[] = "150 file status ok.\r\n";
	char response_151[] = "151 file status not ok.\r\n";

	// input 파일 열기 success
	received_msg(sockfd, plaintext, additional, key, iv);
	intCode = getCode(plaintext);
	if(intCode == 151){
		printf("Input file does not exist.\n");
		return 151;
	}

	// output 파일 열기 success
	ofp = fopen(oFilename, "wb");
  if(ofp == NULL){
		printf("Output file cannot be opened.\n");
		send_msg(sockfd, response_151, additional, key, iv);
		return 151;
	}
	else{
		send_msg(sockfd, response_150, additional, key, iv);
	}

	// input 파일 읽기 success
	received_msg(sockfd, plaintext, additional, key, iv);
	intCode = getCode(plaintext);
	if(intCode == 151){
		printf("Input fread() error\n");
		return 151;
	}

	// cipherfile len 받아오기
	received_msg(sockfd, plaintext, additional, key, iv);
	cipherfile_len = atoi(plaintext);

	// 할당받기
  cipherfile = (unsigned char*)calloc(cipherfile_len, sizeof(unsigned char));
	plainfile = (unsigned char*)calloc(cipherfile_len, sizeof(unsigned char));

	// 암호화 서버 파일 받아오기
	n = readn(*sockfd, cipherfile, cipherfile_len);
	if(n == -1){
		printf("Input cipherfile readn() error\n");
		return 151;
	}
	else if(n == 0){
		printf("received EOF\n");
		return 151;
	}

	// tag 받아오기
	n = readn(*sockfd, tag, 16);
	if(n == -1){
		printf("Input tag readn() error\n");
		return 151;
	}
	else if(n == 0){
		printf("received EOF\n");
		return 151;
	}

  // 암호화 파일 내용 복호화
	plainfile_len = gcm_decrypt(cipherfile, cipherfile_len, additional, strlen((char*)additional), key, iv, plainfile, tag);

	if(plainfile_len >= 0){
		send_msg(sockfd, response_150, additional, key, iv);
		plainfile[plainfile_len] = '\0';
	}
	else{
		printf("Output tag error");
		send_msg(sockfd, response_151, additional, key, iv);
		free_file(plainfile);
		free_file(cipherfile);
	  return 151;
	}

  // 복호화 파일 클라이언트 파일에 쓰기
  fwrite(plainfile, 1, plainfile_len, ofp);
  if(ofp != NULL){
    fclose(ofp);
  }

	// 할당 해제
	free_file(plainfile);
	free_file(cipherfile);

	send_msg(sockfd, response_150, additional, key, iv);

  return 150;
}

int getCode(char *message)
{
	char chaCode[5];

	strncpy(chaCode, message, 4); // 앞에 4개만 복사
	chaCode[4] = '\0'; // 마지막 연결종료로 바꾸기
	return (atoi(chaCode));
}
