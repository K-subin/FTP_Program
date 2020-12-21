#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <signal.h>
#include <sys/wait.h>

#include <assert.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <dirent.h>

#include "../FTP_util/msg.h"
#include "../FTP_util/transfer_enc_socket.h"
#include "../FTP_util/aes_gcm.h"


char response_202[] = "202 Command not implemented\r\n";
char response_220[] = "220 Welcome\r\n";
char response_230[] = "230 User login success\r\n";
char response_231[] = "231 User sign up success\r\n";
char response_331[] = "331 User name exist\r\n";
char response_332[] = "332 User name does not exist\r\n";
char response_200[] = "200 command ok.\r\n";
char response_150[] = "150 file status ok.\r\n";
char response_151[] = "151 file status not ok.\r\n";

int serv_sock; // listening socket
int clnt_sock; // data socket
int intCode;

unsigned char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0X00, };
unsigned char key[AES_KEY_128] = {0x00, };
unsigned char iv[AES_IV_128] = {0x00, };
unsigned char additional[ADDSIZE] = {0x00, };

void read_childproc(int sig);
int find_user_in_DB(char *chaArg, char *pID, char *pPWD);
void write_user_to_DB(char *idArg, char *pwdArg);
int login();
int signup();
int command();
void handle_list();
void handle_down();
void handle_up();
void str_split(char *str, char *strfirst, char *strsecond);

void read_childproc(int sig)
{
  pid_t pid;
  int status;
  pid = waitpid(-1, &status, WNOHANG);
  printf("removed proc id : %d\n", pid);
}

int main(int argc, char* argv[])
{
	struct sockaddr_in serv_addr;  // server's IP and Port
	struct sockaddr_in clnt_addr; // client's IP and Port
	socklen_t clnt_addr_size;

  int state;
  pid_t pid;
  struct sigaction act;

	BIO *bp_public = NULL, *bp_private = NULL;
	RSA *rsa_pubkey = NULL, *rsa_privkey = NULL;

  int cnt_i;
  for(cnt_i = 0; cnt_i < AES_IV_128; cnt_i++){
    iv[cnt_i] = (unsigned char)cnt_i;
  }
  for(cnt_i = 0; cnt_i < ADDSIZE; cnt_i++){
    additional[cnt_i] = (unsigned char)cnt_i;
  }

	if(argc != 2){
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		exit(1);
	}

  act.sa_handler = read_childproc;
  sigemptyset(&act.sa_mask);
  act.sa_flags = 0;
  state = sigaction(SIGCHLD, &act, 0);

	serv_sock = socket(PF_INET, SOCK_STREAM, 0); // IPv4, tcp
	if(serv_sock == -1)
		error_handling("socket() error");

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET; // IPv4
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY); // IP주소 : PC에서 사용가능한 IP주소 자동으 할당
	serv_addr.sin_port = htons(atoi(argv[1]));

	if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1)
		error_handling("bind() error");

	if(listen(serv_sock, 5) == -1)
		error_handling("listen() error");

	// reading public key
	bp_public = BIO_new_file("../FTP_secret/public.pem", "r");
	if(!PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL)){
		error_handling("PEM_read_bio_RSAPublicKey() error");
	}

	// reading private key
	bp_private = BIO_new_file("../FTP_secret/private.pem", "r");
	if(!PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL)){
		error_handling("PEM_read_bio_RSAPublicKey() error");
	}

  while(1)
  {
    clnt_addr_size = sizeof(clnt_addr);
    clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

    if(clnt_sock == -1)
  		continue;
    else
			printf("new client connected\n");

    pid = fork();

    if(pid == 0) // child process
    {
      close(serv_sock);

			set_rsa_key(&clnt_sock, key, iv, rsa_pubkey, rsa_privkey);

      while(1) {
				received_msg(&clnt_sock, plaintext, additional, key, iv);

        if(strncmp("quit", plaintext, 4) == 0)
          break;
        else if(strncmp("login", plaintext, 5) == 0){
          if(login()==230){
						while(1){
							if(command() == 202) break;
						}
          }
        }
        else if(strncmp("signup", plaintext, 6) == 0){
					signup();
        }
      }

      close(clnt_sock);
			printf("[TCP server] Client close : IP = %s, port = %d\n", inet_ntoa(clnt_addr.sin_addr), ntohs(clnt_addr.sin_port));
	  	return 0;
    }
    else // parent process
      close(clnt_sock);
  }

  close(serv_sock);
  return 0;
}


int find_user_in_DB(char *chaArg, char *pID, char *pPWD)
{
	FILE* userDB = NULL;
	int plainDB_len;
  unsigned char* plainDB = NULL;

	// 서버 파일 열기
  userDB = fopen("../FTP_secret/userDB.txt", "rb");
	if(userDB == NULL)
		return 202;

	// 서버 파일 사이즈 구하기
  fseek(userDB, 0, SEEK_END);
  plainDB_len = ftell(userDB);
  fseek(userDB, 0, SEEK_SET);

	if(plainDB_len == 0){
		fclose(userDB);
		return 332;
	}

	// 할당
  plainDB = (unsigned char*)calloc(plainDB_len, sizeof(unsigned char));
  if(plainDB == NULL)
		return 202;

	if(fread(plainDB, 1, plainDB_len, userDB) == 0){
    fprintf(stderr, "fread() error\n");
		return 202;
  }
  if(userDB != NULL)
    fclose(userDB);

  char *ptr = strtok(plainDB, ",");

  while(ptr != NULL){
    str_split(ptr, pID, pPWD);
    if(strcmp(pID, chaArg) == 0){
			free_file(plainDB);
			return 331;
		}
    ptr = strtok(NULL, ",");
	}

	free_file(plainDB);
	return 332;
}


void write_user_to_DB(char *idArg, char *pwdArg)
{
	FILE* idDB = NULL;
	int len;
  char user[BUFSIZE];

	// 서버 파일 이어쓰기로 열기
  idDB = fopen("../FTP_secret/userDB.txt", "ab");
	if(idDB == NULL)
		return;

  sprintf(user, "%s %s,", idArg, pwdArg);
	len = strlen(user);

  fwrite(user, 1, len, idDB);
  if(idDB != NULL)
    fclose(idDB);
}

int signup()
{
	char idArg[STRSIZE], pwdArg[STRSIZE], repwdArg[STRSIZE];
	int idcode, pwdcode;

  char pID[STRSIZE], pPWD[STRSIZE];

	// user id
	received_msg(&clnt_sock, idArg, additional, key, iv);
	idcode = find_user_in_DB(idArg, pID, pPWD);

	if(idcode == 332){ // user id 없음
		send_msg(&clnt_sock, response_332, additional, key, iv);
	}
	else if(idcode == 331){ // user id 이미 있음
		send_msg(&clnt_sock, response_331, additional, key, iv);
		return 0;
	}
	else{ // 에러
		send_msg(&clnt_sock, response_202, additional, key, iv);
		return 0;
	}

	// password
	received_msg(&clnt_sock, pwdArg, additional, key, iv);
	received_msg(&clnt_sock, repwdArg, additional, key, iv);

	if(strcmp(pwdArg, repwdArg)==0){ //패스워드 일치
    write_user_to_DB(idArg, pwdArg);
    send_msg(&clnt_sock, response_231, additional, key, iv);
		return 231;
	}
	else{// 패스워드 불일치
		send_msg(&clnt_sock, response_202, additional, key, iv);
		return 0;
	}

}

int login()
{
  char idArg[STRSIZE];
	char pwdArg[STRSIZE];
	int idCode, pwdcode;

  char pID[STRSIZE], pPWD[STRSIZE];

	// user id
	received_msg(&clnt_sock, idArg, additional, key, iv);
	idCode = find_user_in_DB(idArg, pID, pPWD); // user 찾기

	if(idCode == 332){ // user id 없음
		send_msg(&clnt_sock, response_332, additional, key, iv);
		return 0;
	}
	else if(idCode == 331) // user id 있음
		send_msg(&clnt_sock, response_331, additional, key, iv);
	else if(idCode == 202){
		send_msg(&clnt_sock, response_202, additional, key, iv);
		return 0;
	}

	// password
	received_msg(&clnt_sock, pwdArg, additional, key, iv);

  if(strcmp(pwdArg, pPWD)==0){ // password 일치
    send_msg(&clnt_sock, response_230, additional, key, iv);
		return 230;
  }
  else{  // password 불일치
    send_msg(&clnt_sock, response_202, additional, key, iv);
		return 0;
  }

  return 0;
}

int command()
{
  char chaCmd[BUFSIZE];
  int space_cnt = 0;

	received_msg(&clnt_sock, plaintext, additional, key, iv);
  strcpy(chaCmd, plaintext);
  received_msg(&clnt_sock, plaintext, additional, key, iv);
  space_cnt = atoi(plaintext);

	if(!strcmp(chaCmd, "quit") && space_cnt == 0){
		return 202;
	}
  else if(!strcmp(chaCmd, "list") && space_cnt == 0){
		handle_list();
  }
  else if(!strcmp(chaCmd, "down") && space_cnt == 2){
		handle_down();

  }
  else if(!strcmp(chaCmd, "up") && space_cnt == 2){
		handle_up();
  }

  return 0;
}

void handle_list()
{
	char current_path[BUFSIZE];
	DIR *dp;
	struct dirent *dir;

	getcwd(current_path, sizeof(current_path));
	send_msg(&clnt_sock, current_path, additional, key, iv);

	if((dp = opendir(current_path)) == NULL){
		send_msg(&clnt_sock, response_202, additional, key, iv);
    printf("current path could not be opened.\n");
		return;
	}
	else{
		send_msg(&clnt_sock, response_150, additional, key, iv);

		while(1){
			if((dir = readdir(dp)) == NULL){
				sprintf(plaintext, "%s", "finish");
				send_msg(&clnt_sock, plaintext, additional, key, iv);
				break;
			}

			if(dir->d_ino == 0 || strcmp(".", dir->d_name) == 0 || strcmp("..", dir->d_name) == 0)
				continue;

			sprintf(plaintext, "%s", dir->d_name);
			send_msg(&clnt_sock, plaintext, additional, key, iv);
		}
	}
}

void handle_down()
{
	char iFilename[BUFSIZE];

  received_msg(&clnt_sock, iFilename, additional, key, iv); // 서버 파일 이름 받아오기
  int intCode = send_file(&clnt_sock, iFilename, plaintext, additional, key, iv);	// 암호화 파일 보내기

  if(intCode == 150)
    printf("down success\n");
  else
    printf("down failed\n");
}

void handle_up()
{
	char oFilename[BUFSIZE];

	received_msg(&clnt_sock, oFilename, additional, key, iv);	// 서버 파일 이름 받아오기
	int intCode = received_file(&clnt_sock, oFilename, plaintext, additional, key, iv); // 클라이언트 암호화 파일 복호화해서 저장
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
