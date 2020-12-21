#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include "../FTP_util/msg.h"
#include "../FTP_util/transfer_enc_socket.h"

int sock;
int	intCode;

unsigned char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0X00, };
unsigned char key[AES_KEY_128] = {0x00, };
unsigned char iv[AES_IV_128] = {0x00, };
unsigned char additional[ADDSIZE] = {0x00, };

int getCode(char *message);
int idcheck(const char *text);
int login();
int signup();
int command();
void handle_list();
void handle_down(char chaArg[]);
void handle_up(char chaArg[]);
void str_split(char *str, char *strfirst, char *strsecond);

int main(int argc, char* argv[])
{
	int cnt_i;
  struct sockaddr_in serv_addr;  // server's IP and Port

  for(cnt_i = 0; cnt_i < AES_IV_128; cnt_i++){
    iv[cnt_i] = (unsigned char)cnt_i;
  }
  for(cnt_i = 0; cnt_i < ADDSIZE; cnt_i++){
    additional[cnt_i] = (unsigned char)cnt_i;
  }

	if(argc != 3){
		fprintf(stderr, "%s <IP> <PORT>\n", argv[0]);
		exit(1);
	}

  sock = socket(PF_INET, SOCK_STREAM, 0); // IPv4, TCP
  if(sock == -1){
    error_handling("socket() error");
  }

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
	serv_addr.sin_port = htons(atoi(argv[2]));

  if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
    error_handling("connect() error");
  else
		printf("Welcome to kimsubin's ftp program\n");

	set_rsa_pubkey(&sock, key, iv);

  while (1) {
    printf("===============\n");
    printf("=    login    =\n");
    printf("=    signup   =\n");
    printf("=    quit     =\n");
    printf("===============\n");

		printf("Input a command > ");
    if(fgets(plaintext, BUFSIZE+1, stdin) == NULL)
      break;

		send_msg(&sock, plaintext, additional, key, iv);

		if(strncmp("quit", plaintext, 4) == 0)
			break;
		else if(strncmp("login", plaintext, 5) == 0)
		{
			if(login() == 230){
        while(1){
					if(command() == 202) break;
				}
      }
		}
		else if(strncmp("signup", plaintext, 6) == 0){
			signup();
		}
		else{
			printf("command: login|signup|quit\n");
		}
  }

  close(sock);
  return 0;
}

int idcheck(const char *text){
	char c;

	if(strlen(text) < 6 || strlen(text) > 16)
		return 0;

	for(int i=0; i<strlen(text); i++){
		c = text[i];
		if((c<'0'||c>'9')&&(c<'a'||c>'z')&&(c<'A'||c>'Z'))
			return 0;
	}
	return 1;
}

int signup()
{
	char *pUser, *pPass;
	char chaCode[STRSIZE];

	pUser = (char *)malloc(sizeof(char) * STRSIZE);
	memset(pUser, 0, STRSIZE);

	pPass = (char *)malloc(sizeof(char) * STRSIZE);
	memset(pPass, 0, STRSIZE);

	printf("[Sign up]\n");

	while(1){
		printf("New user id > ");
		fgets(pUser, STRSIZE, stdin);

		pUser[strlen(pUser)-1]='\0';
		if(idcheck(pUser) == 1){
			break;
		}
		else{
			printf("id는 영문, 숫자를 사용하여 6~16자까지 가능합니다.\n");
			memset(pUser, 0, STRSIZE);
		}
	}

	send_msg(&sock, pUser, additional, key, iv); // id 서버로 보낸다.

	received_msg(&sock, plaintext, additional, key, iv);
  intCode = getCode(plaintext); // 서버에 id 있으면 331 받아온다.

	if(intCode == 331){
		printf("User id already exist.\n");
		return 0;
	}
	else if(intCode == 332) {
		while(1){
			pPass = getpass("New password > "); // 비밀번호 화면에 안보이게 하기

			if(strlen(pPass)>=6 && strlen(pPass)<=16){
				break;
			}
			else{
				printf("패스워드는 6~16자까지 가능합니다.\n");
				memset(pPass, 0, STRSIZE);
			}
		}

		send_msg(&sock, pPass, additional, key, iv); // password 서버로 보낸다.

		pPass = getpass("Retype new password > "); // 비밀번호 화면에 안보이게 하기
		send_msg(&sock, pPass, additional, key, iv); // password 서버로 보낸다.
	}
  else {
    error_handling("password error");
		return 0;
	}

	received_msg(&sock, plaintext, additional, key, iv);
 	intCode = getCode(plaintext);

  // Sucess Login
	if(intCode == 231) {
    printf("Sign Up success\n");
	}
	else if(intCode == 202){
		printf("Password do not match.\n");
		return 0;
	}

	free(pUser);
  free(pPass);
  return intCode;
}

int login()
{
	char *pUser, *pPass;
	char chaCode[STRSIZE];

	pUser = (char *)malloc(sizeof(char) * STRSIZE);
	memset(pUser, 0, STRSIZE);

	pPass = (char *)malloc(sizeof(char) * STRSIZE);
	memset(pPass, 0, STRSIZE);

  printf("[Log in]\n");

	while(1){
		printf("User id > ");
		fgets(pUser, STRSIZE, stdin);
		if(strlen(pUser)>1)
			break;
	}
  send_msg(&sock, pUser, additional, key, iv);

	received_msg(&sock, plaintext, additional, key, iv);
  intCode = getCode(plaintext); // 서버에 id 있으면 331 받아온다.

  // make password
	if(intCode == 332){
		printf("User id does not exist.\n");
		return 0;
	}
	else if(intCode == 331) {
		while(1){
			pPass = getpass("Password > "); // 비밀번호 화면에 안보이게 하기
			if(strlen(pPass)!=0)
				break;
		}
	  send_msg(&sock, pPass, additional, key, iv);// password 서버로 보낸다.
	}
  else {
    error_handling("password error");
	}

	received_msg(&sock, plaintext, additional, key, iv);
 	intCode = getCode(plaintext); // 서버에 pwd있으면 230 받아온다.

  // Sucess Login
	if(intCode == 230) {
    printf("Login success.\n");
	}
  else {
		printf("Login fail.\n");
		return 0;
	}

	free(pUser); free(pPass);

  return intCode;
}

int command()
{
	char *pCommand;
  char command[BUFSIZE];
  char chaCmd[BUFSIZE], chaArg[BUFSIZE];
  int space_cnt = 0;

  printf("ftp > ");
	if(fgets(command, BUFSIZE+1, stdin) == NULL)
		return 0;

  if((pCommand = strchr(command, '\n')) != NULL) // \n 문자 찾아서 \0으로 바꿔줌
    *pCommand = '\0';

  for(int i = 0; i<strlen(command); i++){ // 빈칸 개수 세기
    if(command[i] == ' ')
      space_cnt += 1;
  }

  sprintf(plaintext, "%d", space_cnt);
  str_split(command, chaCmd, chaArg); // 빈칸 기준으로 나누기

  send_msg(&sock, chaCmd, additional, key, iv); // 명령어
  send_msg(&sock, plaintext, additional, key, iv); // 빈칸 개수

  if(!strcmp(chaCmd, "quit")) {
    if(space_cnt != 0){
      printf("input <quit>\n");
      return 0;
    }
		return 202;
  }
  else if(!strcmp(chaCmd, "list")) {
    if(space_cnt != 0){
      printf("input <list>\n");
      return 0;
    }
    handle_list();
  }
	else if(!strcmp(chaCmd, "down")) {
    if(space_cnt != 2){
      printf("input <down filename1 filename2>\n");
      return 0;
    }
    handle_down(chaArg);
  }
	else if(!strcmp(chaCmd, "up")){
    if(space_cnt != 2){
      printf("input <up filename1 filename2>\n");
      return 0;
    }
    handle_up(chaArg);
  }
	else {
    printf("command: list|down|up|quit\n");
  }

  return 0;
}

void handle_list()
{
	char current_path[BUFSIZE];
  int	cnt=0;

	received_msg(&sock, current_path, additional, key, iv);
	printf("Current Directory : %s\n", current_path);

	received_msg(&sock, plaintext, additional, key, iv);
  intCode = getCode(plaintext);
  if(intCode == 202) {
    printf("current path could not be opened.\n");
		return;
  }

	while(1){
		received_msg(&sock, plaintext, additional, key, iv);
		if(strncmp("finish", plaintext, 6) == 0){
			printf("\n");
			break;
		}

		printf("%-20s", plaintext);

		cnt++;
		if(cnt%4 == 0)
			printf("\n");
	}
}

void handle_down(char chaArg[])
{
	char *pChaArg;
  char iFilename[BUFSIZE];
	char oFilename[BUFSIZE];

	str_split(chaArg, iFilename, oFilename); // 빈칸 기준으로 나누기
	send_msg(&sock, iFilename, additional, key, iv); // 서버 파일 이름 보내기

  intCode = received_file(&sock, oFilename, plaintext, additional, key, iv); // 서버 암호화 파일 복호화해서 저장
  if(intCode == 150)
    printf("down success\n");
  else
    printf("down failed\n");
}

void handle_up(char chaArg[])
{
	char *pChaArg;
  char iFilename[BUFSIZE];
	char oFilename[BUFSIZE];

  str_split(chaArg, iFilename, oFilename); // 빈칸 기준으로 나누기
  send_msg(&sock, oFilename, additional, key, iv); // 서버 파일 이름 보내기

  intCode = send_file(&sock, iFilename, plaintext, additional, key, iv);	// 암호화 파일 보내기
  if(intCode == 150)
    printf("up success\n");
  else
    printf("up failed\n");
}

void str_split(char *str, char *strfirst, char *strsecond)
{
	char *pStr;

	memset(strfirst, 0, sizeof(strfirst));
	memset(strsecond, 0, sizeof(strsecond));

	// 빈칸 뒤 문자열
	if((pStr = strchr(str, ' ')) == NULL) {
    strcpy(strfirst, str);
    strcpy(strsecond, "");
  }
  else { // 빈칸 있는 곳에 \0 저장, 파라매터에
    strncpy(strfirst, str, pStr - str);
    strfirst[pStr-str] = '\0';
    strcpy(strsecond, pStr + 1);
  }
}
