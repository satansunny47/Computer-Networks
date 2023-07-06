// Group_no - 62 :
// Pranil Dey (20CS30038)
// Yuti Patel (20CS10043)

#include "mysocket.h"
struct message_table
{
    int head;
    int tail;
    char *message;
};

void enqueue(struct message_table *q, char *message)
{
    q->message = message;
    q->tail++;
}

char *dequeue(struct message_table *q)
{
    char *message = q->message;
    q->head++;
    return message;
}

void init_queue(struct message_table *q)
{
    q->head = 0;
    q->tail = 0;
}

struct message_table *Send_message, *Receive_message;
pthread_t R, S;
int recv_sockfd = -1, send_sockfd = -1;

void *Send_thread(void* sockfd)
{
        printf("Sending message\n");
    while(1){
        if(send_sockfd == -1)
        continue;
        if(Send_message->head == Send_message->tail){
            sleep(10);
            continue;
        }
        char *msg=dequeue(Send_message);
        int msg_length=strlen(msg);
       
        char buff[4+msg_length];
        for(int i=0;i<5;i++) buff[i]='0';
        char temp[4];
        snprintf(temp,4,"%d",msg_length);
         printf("Message length %s\n",temp);
        int j=4;
        for(int i=strlen(temp);i>=0;i--) buff[j--]=temp[i];
        for(int i=0;i<msg_length;i++) buff[i+4]=msg[i];
        send(send_sockfd,buff,strlen(buff)+1,0);
        printf("Message %s",buff);
        printf("Message sent\n");
    }
}

void *Receive_thread(void* sockfd)
{
    char buf[5004];
    while (1)
    {
        if(recv_sockfd == -1){
            continue;
        }
        int recv_len = recv(recv_sockfd, buf, 4, 0);
        if(recv_len<=0) continue;

        int total_recv_len=0;
        while (recv_len < 4)
        {
            char temp[4];
            recv_len = recv(recv_sockfd, temp, 4, 0);
            for (int i = 0; i < recv_len; i++)
            {
                buf[i + total_recv_len] = temp[i];
            }
            total_recv_len += recv_len;
        }
        char len[4];
        for (int i = 0; i < 4; i++)
        {
            len[i] = buf[i];
        }
        int length = atoi(len);
        printf("Message length %d\n",length);
        while (total_recv_len < length)
        {
            char temp[1000];
            recv_len = recv(recv_sockfd, temp, 1000, 0);
            memcpy(buf + total_recv_len, temp, recv_len);
            total_recv_len += recv_len;
        }
        while (Receive_message->tail - Receive_message->head > 9)
        {
            continue;
        }
        char *message = (char *)malloc(sizeof(char) * length);
        memcpy(message, buf, length);
        enqueue(Receive_message, message);
    }
}

int my_socket(int domain, int type, int protocol)
{
    int sockfd = socket(domain, SOCK_STREAM, protocol);
    if (sockfd < 0)
    {
        perror("unable to create socket\n");
        exit(1);
    }

    Send_message = (struct queue *)malloc(sizeof(struct queue));
    Receive_message = (struct queue *)malloc(sizeof(struct queue));

    init_queue(Send_message);
    init_queue(Receive_message);
    printf("Socket created\n");
    pthread_create(&R, NULL, Receive_thread, sockfd);
    pthread_create(&S, NULL, Send_thread, sockfd);
    return sockfd;
}

int my_listen(int sockfd, int backlog)
{
    int ret = listen(sockfd, backlog);
    if (ret == -1)
    {
        perror("listen");
        exit(1);
    }
    return ret;
}

int my_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int ret = accept(sockfd, addr, addrlen);
    if (ret == -1)
    {
        perror("accept");
        exit(1);
    }
    return ret;
}

int my_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret = bind(sockfd, addr, addrlen);
    if (ret == -1)
    {
        perror("bind");
        exit(1);
    }
    return ret;
}

int my_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    int ret = connect(sockfd, addr, addrlen);
    if (ret == -1)
    {
        perror("connect");
        exit(1);
    }
    return ret;
}

ssize_t my_recv(int sockfd, void *buf, size_t len, int flags)
{
    recv_sockfd = sockfd;
    while (Receive_message->head == Receive_message->tail)
    {
        continue;
    }
    char *message = dequeue(Receive_message);
    ssize_t ret = strlen(message);
    memcpy(buf, message, len);
    free(message);
    return ret;
}

ssize_t my_send(int sockfd, const void *buf, ssize_t len, int flags)
{
    send_sockfd = sockfd;
    printf("Send_sockfd: %d\n", send_sockfd);
    char *message = (char *)malloc(sizeof(char) * len);
        
    while(Send_message->tail - Receive_message->head >9){
        continue;
    }

    memcpy(message, buf, len);
    Send_message->message=(char *)malloc(sizeof(char)*len);
    for(int i=0; i<len; i++){
        Send_message->message[i] = message[i];
    }
    Send_message->tail++;
    printf("Message:  %s\n", (char *)buf);
    return len;    
}

void my_close(int sockfd)
{
    sleep(10);
    close(sockfd);

    free(Send_message);
    free(Receive_message);

    pthread_cancel(R);
    pthread_cancel(S);
}
