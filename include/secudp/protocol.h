/** 
 @file  protocol.h
 @brief SecUdp protocol
*/
#ifndef __SECUDP_PROTOCOL_H__
#define __SECUDP_PROTOCOL_H__

#include "secudp/types.h"

enum
{
   SECUDP_PROTOCOL_MINIMUM_MTU             = 576,
   SECUDP_PROTOCOL_MAXIMUM_MTU             = 4096,
   SECUDP_PROTOCOL_MAXIMUM_PACKET_COMMANDS = 32,
   SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE     = 4096,
   SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE     = 65536,
   SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT   = 1,
   SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT   = 255,
   SECUDP_PROTOCOL_MAXIMUM_PEER_ID         = 0xFFF,
   SECUDP_PROTOCOL_MAXIMUM_FRAGMENT_COUNT  = 1024 * 1024
};

typedef enum _SecUdpProtocolCommand
{
   SECUDP_PROTOCOL_COMMAND_NONE               = 0,
   SECUDP_PROTOCOL_COMMAND_ACKNOWLEDGE        = 1,
   SECUDP_PROTOCOL_COMMAND_CONNECT            = 2,
   SECUDP_PROTOCOL_COMMAND_VERIFY_CONNECT     = 3,
   SECUDP_PROTOCOL_COMMAND_DISCONNECT         = 4,
   SECUDP_PROTOCOL_COMMAND_PING               = 5,
   SECUDP_PROTOCOL_COMMAND_SEND_RELIABLE      = 6,
   SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE    = 7,
   SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT      = 8,
   SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED   = 9,
   SECUDP_PROTOCOL_COMMAND_BANDWIDTH_LIMIT    = 10,
   SECUDP_PROTOCOL_COMMAND_THROTTLE_CONFIGURE = 11,
   SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT = 12,
   SECUDP_PROTOCOL_COMMAND_COUNT              = 13,

   SECUDP_PROTOCOL_COMMAND_MASK               = 0x0F
} SecUdpProtocolCommand;

typedef enum _SecUdpProtocolFlag
{
   SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE = (1 << 7),
   SECUDP_PROTOCOL_COMMAND_FLAG_UNSEQUENCED = (1 << 6),

   SECUDP_PROTOCOL_HEADER_FLAG_COMPRESSED = (1 << 14),
   SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME  = (1 << 15),
   SECUDP_PROTOCOL_HEADER_FLAG_MASK       = SECUDP_PROTOCOL_HEADER_FLAG_COMPRESSED | SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME,

   SECUDP_PROTOCOL_HEADER_SESSION_MASK    = (3 << 12),
   SECUDP_PROTOCOL_HEADER_SESSION_SHIFT   = 12
} SecUdpProtocolFlag;

#ifdef _MSC_VER
#pragma pack(push, 1)
#define SECUDP_PACKED
#elif defined(__GNUC__) || defined(__clang__)
#define SECUDP_PACKED __attribute__ ((packed))
#else
#define SECUDP_PACKED
#endif

typedef struct _SecUdpProtocolHeader
{
   secudp_uint16 peerID;
   secudp_uint16 sentTime;
} SECUDP_PACKED SecUdpProtocolHeader;

typedef struct _SecUdpProtocolCommandHeader
{
   secudp_uint8 command;
   secudp_uint8 channelID;
   secudp_uint16 reliableSequenceNumber;
} SECUDP_PACKED SecUdpProtocolCommandHeader;

typedef struct _SecUdpProtocolAcknowledge
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 receivedReliableSequenceNumber;
   secudp_uint16 receivedSentTime;
} SECUDP_PACKED SecUdpProtocolAcknowledge;

typedef struct _SecUdpProtocolConnect
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 outgoingPeerID;
   secudp_uint8  incomingSessionID;
   secudp_uint8  outgoingSessionID;
   secudp_uint32 mtu;
   secudp_uint32 windowSize;
   secudp_uint32 channelCount;
   secudp_uint32 incomingBandwidth;
   secudp_uint32 outgoingBandwidth;
   secudp_uint32 packetThrottleInterval;
   secudp_uint32 packetThrottleAcceleration;
   secudp_uint32 packetThrottleDeceleration;
   secudp_uint32 connectID;
   secudp_uint32 data;
} SECUDP_PACKED SecUdpProtocolConnect;

typedef struct _SecUdpProtocolVerifyConnect
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 outgoingPeerID;
   secudp_uint8  incomingSessionID;
   secudp_uint8  outgoingSessionID;
   secudp_uint32 mtu;
   secudp_uint32 windowSize;
   secudp_uint32 channelCount;
   secudp_uint32 incomingBandwidth;
   secudp_uint32 outgoingBandwidth;
   secudp_uint32 packetThrottleInterval;
   secudp_uint32 packetThrottleAcceleration;
   secudp_uint32 packetThrottleDeceleration;
   secudp_uint32 connectID;
} SECUDP_PACKED SecUdpProtocolVerifyConnect;

typedef struct _SecUdpProtocolBandwidthLimit
{
   SecUdpProtocolCommandHeader header;
   secudp_uint32 incomingBandwidth;
   secudp_uint32 outgoingBandwidth;
} SECUDP_PACKED SecUdpProtocolBandwidthLimit;

typedef struct _SecUdpProtocolThrottleConfigure
{
   SecUdpProtocolCommandHeader header;
   secudp_uint32 packetThrottleInterval;
   secudp_uint32 packetThrottleAcceleration;
   secudp_uint32 packetThrottleDeceleration;
} SECUDP_PACKED SecUdpProtocolThrottleConfigure;

typedef struct _SecUdpProtocolDisconnect
{
   SecUdpProtocolCommandHeader header;
   secudp_uint32 data;
} SECUDP_PACKED SecUdpProtocolDisconnect;

typedef struct _SecUdpProtocolPing
{
   SecUdpProtocolCommandHeader header;
} SECUDP_PACKED SecUdpProtocolPing;

typedef struct _SecUdpProtocolSendReliable
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 dataLength;
} SECUDP_PACKED SecUdpProtocolSendReliable;

typedef struct _SecUdpProtocolSendUnreliable
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 unreliableSequenceNumber;
   secudp_uint16 dataLength;
} SECUDP_PACKED SecUdpProtocolSendUnreliable;

typedef struct _SecUdpProtocolSendUnsequenced
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 unsequencedGroup;
   secudp_uint16 dataLength;
} SECUDP_PACKED SecUdpProtocolSendUnsequenced;

typedef struct _SecUdpProtocolSendFragment
{
   SecUdpProtocolCommandHeader header;
   secudp_uint16 startSequenceNumber;
   secudp_uint16 dataLength;
   secudp_uint32 fragmentCount;
   secudp_uint32 fragmentNumber;
   secudp_uint32 totalLength;
   secudp_uint32 fragmentOffset;
} SECUDP_PACKED SecUdpProtocolSendFragment;

typedef union _SecUdpProtocol
{
   SecUdpProtocolCommandHeader header;
   SecUdpProtocolAcknowledge acknowledge;
   SecUdpProtocolConnect connect;
   SecUdpProtocolVerifyConnect verifyConnect;
   SecUdpProtocolDisconnect disconnect;
   SecUdpProtocolPing ping;
   SecUdpProtocolSendReliable sendReliable;
   SecUdpProtocolSendUnreliable sendUnreliable;
   SecUdpProtocolSendUnsequenced sendUnsequenced;
   SecUdpProtocolSendFragment sendFragment;
   SecUdpProtocolBandwidthLimit bandwidthLimit;
   SecUdpProtocolThrottleConfigure throttleConfigure;
} SECUDP_PACKED SecUdpProtocol;

#ifdef _MSC_VER
#pragma pack(pop)
#endif

#endif /* __SECUDP_PROTOCOL_H__ */

