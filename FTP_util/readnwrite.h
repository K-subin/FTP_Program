#ifndef _READNWRITE_H_
#define _READNWRITE_H_

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

ssize_t
readn(int fd, void* vptr, size_t n);

ssize_t
writen(int fd, const void* vptr, size_t n);

#endif

//EOF
