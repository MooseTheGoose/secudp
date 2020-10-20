/** 
 @file  win32.h
 @brief SecUdp Win32 header
*/
#ifndef __SECUDP_WIN32_H__
#define __SECUDP_WIN32_H__

#ifdef _MSC_VER
#ifdef SECUDP_BUILDING_LIB
#pragma warning (disable: 4267) // size_t to int conversion
#pragma warning (disable: 4244) // 64bit to 32bit int
#pragma warning (disable: 4018) // signed/unsigned mismatch
#pragma warning (disable: 4146) // unary minus operator applied to unsigned type
#endif
#endif

#include <stdlib.h>
#include <winsock2.h>

typedef SOCKET SecUdpSocket;

#define SECUDP_SOCKET_NULL INVALID_SOCKET

#define SECUDP_HOST_TO_NET_16(value) (htons (value))
#define SECUDP_HOST_TO_NET_32(value) (htonl (value))

#define SECUDP_NET_TO_HOST_16(value) (ntohs (value))
#define SECUDP_NET_TO_HOST_32(value) (ntohl (value))

typedef struct
{
    size_t dataLength;
    void * data;
} SecUdpBuffer;

#define SECUDP_CALLBACK __cdecl

#ifdef SECUDP_DLL
#ifdef SECUDP_BUILDING_LIB
#define SECUDP_API __declspec( dllexport )
#else
#define SECUDP_API __declspec( dllimport )
#endif /* SECUDP_BUILDING_LIB */
#else /* !SECUDP_DLL */
#define SECUDP_API extern
#endif /* SECUDP_DLL */

typedef fd_set SecUdpSocketSet;

#define SECUDP_SOCKETSET_EMPTY(sockset)          FD_ZERO (& (sockset))
#define SECUDP_SOCKETSET_ADD(sockset, socket)    FD_SET (socket, & (sockset))
#define SECUDP_SOCKETSET_REMOVE(sockset, socket) FD_CLR (socket, & (sockset))
#define SECUDP_SOCKETSET_CHECK(sockset, socket)  FD_ISSET (socket, & (sockset))

#endif /* __SECUDP_WIN32_H__ */


