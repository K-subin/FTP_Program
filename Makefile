CC=gcc
LDFLAGS=-lcrypto

UTIL_SRCS = FTP_util/aes_gcm.c FTP_util/readnwrite.c FTP_util/transfer_enc_socket.c

SERVER = FTP_server/ftp_server
SERVER_SRCS = FTP_server/ftp_server.c

CLIENT = FTP_client/ftp_client
CLIENT_SRCS = FTP_client/ftp_client.c

all:$(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRCS) $(UTIL_SRCS)
		$(CC) -o $@ $^ $(LDFLAGS)

$(CLIENT): $(CLIENT_SRCS) $(UTIL_SRCS)
		$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm $(SERVER)
	rm $(CLIENT)
