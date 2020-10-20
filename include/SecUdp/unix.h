/** 
 @file  unix.h
 @brief SecUdp Unix header
*/
#ifndef __SECUDP_UNIX_H__
#define __SECUDP_UNIX_H__

#include <stdlib.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

#ifdef MSG_MAXIOVLEN
#define SECUDP_BUFFER_MAXIMUM MSG_MAXIOVLEN
#endif

typedef int SecUdpSocket;

#define SECUDP_SOCKET_NULL -1

#define SECUDP_HOST_TO_NET_16(value) (htons (value)) /**< macro that converts host to net byte-order of a 16-bit value */
#define SECUDP_HOST_TO_NET_32(value) (htonl (value)) /**< macro that converts host to net byte-order of a 32-bit value */

#define SECUDP_NET_TO_HOST_16(value) (ntohs (value)) /**< macro that converts net to host byte-order of a 16-bit value */
#define SECUDP_NET_TO_HOST_32(value) (ntohl (value)) /**< macro that converts net to host byte-order of a 32-bit value */

typedef struct
{
    void * data;
    size_t dataLength;
} SecUdpBuffer;

#define SECUDP_CALLBACK

#define SECUDP_API extern

typedef fd_set SecUdpSocketSet;

#define SECUDP_SOCKETSET_EMPTY(sockset)          FD_ZERO (& (sockset))
#define SECUDP_SOCKETSET_ADD(sockset, socket)    FD_SET (socket, & (sockset))
#define SECUDP_SOCKETSET_REMOVE(sockset, socket) FD_CLR (socket, & (sockset))
#define SECUDP_SOCKETSET_CHECK(sockset, socket)  FD_ISSET (socket, & (sockset))
    
#endif /* __SECUDP_UNIX_H__ */

