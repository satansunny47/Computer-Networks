// Group_no - 62 :
// Pranil Dey (20CS30038)
// Yuti Patel (20CS10043)

#ifndef MYSOCKET_H 
#define MYSOCKET_H
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/socket.h>

#define SOCK_MyTCP 100

void *Receive_thread(void* sockfd);

void *Send_thread(void* sockfd);

int my_socket(int domain, int type, int protocol);

int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int my_listen(int sockfd, int backlog);

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

ssize_t my_send(int sockfd, const void *buf, ssize_t len, int flags);

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags);

void my_close(int sockfd);

typedef struct message_table
{
    int head;
    int tail;
    char *message;
}message_table;

#endif