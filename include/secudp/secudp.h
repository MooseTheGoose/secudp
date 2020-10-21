/** 
 @file  secudp.h
 @brief SecUdp public header file
*/
#ifndef __SECUDP_SECUDP_H__
#define __SECUDP_SECUDP_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdlib.h>

#ifdef _WIN32
#include "secudp/win32.h"
#else
#include "secudp/unix.h"
#endif

#include "secudp/types.h"
#include "secudp/protocol.h"
#include "secudp/list.h"
#include "secudp/callbacks.h"

#define SECUDP_VERSION_MAJOR 1
#define SECUDP_VERSION_MINOR 3
#define SECUDP_VERSION_PATCH 16
#define SECUDP_VERSION_CREATE(major, minor, patch) (((major)<<16) | ((minor)<<8) | (patch))
#define SECUDP_VERSION_GET_MAJOR(version) (((version)>>16)&0xFF)
#define SECUDP_VERSION_GET_MINOR(version) (((version)>>8)&0xFF)
#define SECUDP_VERSION_GET_PATCH(version) ((version)&0xFF)
#define SECUDP_VERSION SECUDP_VERSION_CREATE(SECUDP_VERSION_MAJOR, SECUDP_VERSION_MINOR, SECUDP_VERSION_PATCH)

typedef secudp_uint32 SecUdpVersion;

struct _SecUdpHost;
struct _SecUdpEvent;
struct _SecUdpPacket;

typedef enum _SecUdpSocketType
{
   SECUDP_SOCKET_TYPE_STREAM   = 1,
   SECUDP_SOCKET_TYPE_DATAGRAM = 2
} SecUdpSocketType;

typedef enum _SecUdpSocketWait
{
   SECUDP_SOCKET_WAIT_NONE      = 0,
   SECUDP_SOCKET_WAIT_SEND      = (1 << 0),
   SECUDP_SOCKET_WAIT_RECEIVE   = (1 << 1),
   SECUDP_SOCKET_WAIT_INTERRUPT = (1 << 2)
} SecUdpSocketWait;

typedef enum _SecUdpSocketOption
{
   SECUDP_SOCKOPT_NONBLOCK  = 1,
   SECUDP_SOCKOPT_BROADCAST = 2,
   SECUDP_SOCKOPT_RCVBUF    = 3,
   SECUDP_SOCKOPT_SNDBUF    = 4,
   SECUDP_SOCKOPT_REUSEADDR = 5,
   SECUDP_SOCKOPT_RCVTIMEO  = 6,
   SECUDP_SOCKOPT_SNDTIMEO  = 7,
   SECUDP_SOCKOPT_ERROR     = 8,
   SECUDP_SOCKOPT_NODELAY   = 9
} SecUdpSocketOption;

typedef enum _SecUdpSocketShutdown
{
    SECUDP_SOCKET_SHUTDOWN_READ       = 0,
    SECUDP_SOCKET_SHUTDOWN_WRITE      = 1,
    SECUDP_SOCKET_SHUTDOWN_READ_WRITE = 2
} SecUdpSocketShutdown;

#define SECUDP_HOST_ANY       0
#define SECUDP_HOST_BROADCAST 0xFFFFFFFFU
#define SECUDP_PORT_ANY       0

/**
 * Portable internet address structure. 
 *
 * The host must be specified in network byte-order, and the port must be in host 
 * byte-order. The constant SECUDP_HOST_ANY may be used to specify the default 
 * server host. The constant SECUDP_HOST_BROADCAST may be used to specify the
 * broadcast address (255.255.255.255).  This makes sense for secudp_host_connect,
 * but not for secudp_host_create.  Once a server responds to a broadcast, the
 * address is updated from SECUDP_HOST_BROADCAST to the server's actual IP address.
 */
typedef struct _SecUdpAddress
{
   secudp_uint32 host;
   secudp_uint16 port;
} SecUdpAddress;

/**
 * Packet flag bit constants.
 *
 * The host must be specified in network byte-order, and the port must be in
 * host byte-order. The constant SECUDP_HOST_ANY may be used to specify the
 * default server host.
 
   @sa SecUdpPacket
*/
typedef enum _SecUdpPacketFlag
{
   /** packet must be received by the target peer and resend attempts should be
     * made until the packet is delivered */
   SECUDP_PACKET_FLAG_RELIABLE    = (1 << 0),
   /** packet will not be sequenced with other packets
     * not supported for reliable packets
     */
   SECUDP_PACKET_FLAG_UNSEQUENCED = (1 << 1),
   /** packet will not allocate data, and user must supply it instead */
   SECUDP_PACKET_FLAG_NO_ALLOCATE = (1 << 2),
   /** packet will be fragmented using unreliable (instead of reliable) sends
     * if it exceeds the MTU */
   SECUDP_PACKET_FLAG_UNRELIABLE_FRAGMENT = (1 << 3),

   /** whether the packet has been sent from all queues it has been entered into */
   SECUDP_PACKET_FLAG_SENT = (1<<8)
} SecUdpPacketFlag;

typedef void (SECUDP_CALLBACK * SecUdpPacketFreeCallback) (struct _SecUdpPacket *);

/**
 * SecUdp packet structure.
 *
 * An SecUdp data packet that may be sent to or received from a peer. The shown 
 * fields should only be read and never modified. The data field contains the 
 * allocated data for the packet. The dataLength fields specifies the length 
 * of the allocated data.  The flags field is either 0 (specifying no flags), 
 * or a bitwise-or of any combination of the following flags:
 *
 *    SECUDP_PACKET_FLAG_RELIABLE - packet must be received by the target peer
 *    and resend attempts should be made until the packet is delivered
 *
 *    SECUDP_PACKET_FLAG_UNSEQUENCED - packet will not be sequenced with other packets 
 *    (not supported for reliable packets)
 *
 *    SECUDP_PACKET_FLAG_NO_ALLOCATE - packet will not allocate data, and user must supply it instead
 *
 *    SECUDP_PACKET_FLAG_UNRELIABLE_FRAGMENT - packet will be fragmented using unreliable
 *    (instead of reliable) sends if it exceeds the MTU
 *
 *    SECUDP_PACKET_FLAG_SENT - whether the packet has been sent from all queues it has been entered into
   @sa SecUdpPacketFlag
 */
typedef struct _SecUdpPacket
{
   size_t                   referenceCount;  /**< internal use only */
   secudp_uint32              flags;           /**< bitwise-or of SecUdpPacketFlag constants */
   secudp_uint8 *             data;            /**< allocated data for packet */
   size_t                   dataLength;      /**< length of data */
   SecUdpPacketFreeCallback   freeCallback;    /**< function to be called when the packet is no longer in use */
   void *                   userData;        /**< application private data, may be freely modified */
} SecUdpPacket;

typedef struct _SecUdpAcknowledgement
{
   SecUdpListNode acknowledgementList;
   secudp_uint32  sentTime;
   SecUdpProtocol command;
} SecUdpAcknowledgement;

typedef struct _SecUdpOutgoingCommand
{
   SecUdpListNode outgoingCommandList;
   secudp_uint16  reliableSequenceNumber;
   secudp_uint16  unreliableSequenceNumber;
   secudp_uint32  sentTime;
   secudp_uint32  roundTripTimeout;
   secudp_uint32  roundTripTimeoutLimit;
   secudp_uint32  fragmentOffset;
   secudp_uint16  fragmentLength;
   secudp_uint16  sendAttempts;
   SecUdpProtocol command;
   SecUdpPacket * packet;
} SecUdpOutgoingCommand;

typedef struct _SecUdpIncomingCommand
{  
   SecUdpListNode     incomingCommandList;
   secudp_uint16      reliableSequenceNumber;
   secudp_uint16      unreliableSequenceNumber;
   SecUdpProtocol     command;
   secudp_uint32      fragmentCount;
   secudp_uint32      fragmentsRemaining;
   secudp_uint32 *    fragments;
   SecUdpPacket *     packet;
} SecUdpIncomingCommand;

typedef enum _SecUdpPeerState
{
   SECUDP_PEER_STATE_DISCONNECTED                = 0,
   SECUDP_PEER_STATE_CONNECTING                  = 1,
   SECUDP_PEER_STATE_ACKNOWLEDGING_CONNECT       = 2,
   SECUDP_PEER_STATE_CONNECTION_PENDING          = 3,
   SECUDP_PEER_STATE_CONNECTION_SUCCEEDED        = 4,
   SECUDP_PEER_STATE_CONNECTED                   = 5,
   SECUDP_PEER_STATE_DISCONNECT_LATER            = 6,
   SECUDP_PEER_STATE_DISCONNECTING               = 7,
   SECUDP_PEER_STATE_ACKNOWLEDGING_DISCONNECT    = 8,
   SECUDP_PEER_STATE_ZOMBIE                      = 9 
} SecUdpPeerState;

#ifndef SECUDP_BUFFER_MAXIMUM
#define SECUDP_BUFFER_MAXIMUM (1 + 2 * SECUDP_PROTOCOL_MAXIMUM_PACKET_COMMANDS)
#endif

enum
{
   SECUDP_HOST_RECEIVE_BUFFER_SIZE          = 256 * 1024,
   SECUDP_HOST_SEND_BUFFER_SIZE             = 256 * 1024,
   SECUDP_HOST_BANDWIDTH_THROTTLE_INTERVAL  = 1000,
   SECUDP_HOST_DEFAULT_MTU                  = 1400,
   SECUDP_HOST_DEFAULT_MAXIMUM_PACKET_SIZE  = 32 * 1024 * 1024,
   SECUDP_HOST_DEFAULT_MAXIMUM_WAITING_DATA = 32 * 1024 * 1024,

   SECUDP_PEER_DEFAULT_ROUND_TRIP_TIME      = 500,
   SECUDP_PEER_DEFAULT_PACKET_THROTTLE      = 32,
   SECUDP_PEER_PACKET_THROTTLE_SCALE        = 32,
   SECUDP_PEER_PACKET_THROTTLE_COUNTER      = 7, 
   SECUDP_PEER_PACKET_THROTTLE_ACCELERATION = 2,
   SECUDP_PEER_PACKET_THROTTLE_DECELERATION = 2,
   SECUDP_PEER_PACKET_THROTTLE_INTERVAL     = 5000,
   SECUDP_PEER_PACKET_LOSS_SCALE            = (1 << 16),
   SECUDP_PEER_PACKET_LOSS_INTERVAL         = 10000,
   SECUDP_PEER_WINDOW_SIZE_SCALE            = 64 * 1024,
   SECUDP_PEER_TIMEOUT_LIMIT                = 32,
   SECUDP_PEER_TIMEOUT_MINIMUM              = 5000,
   SECUDP_PEER_TIMEOUT_MAXIMUM              = 30000,
   SECUDP_PEER_PING_INTERVAL                = 500,
   SECUDP_PEER_UNSEQUENCED_WINDOWS          = 64,
   SECUDP_PEER_UNSEQUENCED_WINDOW_SIZE      = 1024,
   SECUDP_PEER_FREE_UNSEQUENCED_WINDOWS     = 32,
   SECUDP_PEER_RELIABLE_WINDOWS             = 16,
   SECUDP_PEER_RELIABLE_WINDOW_SIZE         = 0x1000,
   SECUDP_PEER_FREE_RELIABLE_WINDOWS        = 8
};

typedef struct _SecUdpChannel
{
   secudp_uint16  outgoingReliableSequenceNumber;
   secudp_uint16  outgoingUnreliableSequenceNumber;
   secudp_uint16  usedReliableWindows;
   secudp_uint16  reliableWindows [SECUDP_PEER_RELIABLE_WINDOWS];
   secudp_uint16  incomingReliableSequenceNumber;
   secudp_uint16  incomingUnreliableSequenceNumber;
   SecUdpList     incomingReliableCommands;
   SecUdpList     incomingUnreliableCommands;
} SecUdpChannel;

typedef enum _SecUdpPeerFlag
{
   SECUDP_PEER_FLAG_NEEDS_DISPATCH = (1 << 0)
} SecUdpPeerFlag;

typedef struct _SecUdpPeerSecret {
  secudp_uint32 mac_key[8];
  secudp_uint32 chacha_key[8];
} SecUdpPeerSecret;

/**
 * An SecUdp peer which data packets may be sent or received from. 
 *
 * No fields should be modified unless otherwise specified. 
 */
typedef struct _SecUdpPeer
{ 
   SecUdpListNode  dispatchList;
   struct _SecUdpHost * host;
   secudp_uint16   outgoingPeerID;
   secudp_uint16   incomingPeerID;
   secudp_uint32   connectID;
   secudp_uint8    outgoingSessionID;
   secudp_uint8    incomingSessionID;
   SecUdpAddress   address;            /**< Internet address of the peer */
   void *        data;               /**< Application private data, may be freely modified */
   SecUdpPeerState state;
   SecUdpChannel * channels;
   size_t        channelCount;       /**< Number of channels allocated for communication with peer */
   secudp_uint32   incomingBandwidth;  /**< Downstream bandwidth of the client in bytes/second */
   secudp_uint32   outgoingBandwidth;  /**< Upstream bandwidth of the client in bytes/second */
   secudp_uint32   incomingBandwidthThrottleEpoch;
   secudp_uint32   outgoingBandwidthThrottleEpoch;
   secudp_uint32   incomingDataTotal;
   secudp_uint32   outgoingDataTotal;
   secudp_uint32   lastSendTime;
   secudp_uint32   lastReceiveTime;
   secudp_uint32   nextTimeout;
   secudp_uint32   earliestTimeout;
   secudp_uint32   packetLossEpoch;
   secudp_uint32   packetsSent;
   secudp_uint32   packetsLost;
   secudp_uint32   packetLoss;          /**< mean packet loss of reliable packets as a ratio with respect to the constant SECUDP_PEER_PACKET_LOSS_SCALE */
   secudp_uint32   packetLossVariance;
   secudp_uint32   packetThrottle;
   secudp_uint32   packetThrottleLimit;
   secudp_uint32   packetThrottleCounter;
   secudp_uint32   packetThrottleEpoch;
   secudp_uint32   packetThrottleAcceleration;
   secudp_uint32   packetThrottleDeceleration;
   secudp_uint32   packetThrottleInterval;
   secudp_uint32   pingInterval;
   secudp_uint32   timeoutLimit;
   secudp_uint32   timeoutMinimum;
   secudp_uint32   timeoutMaximum;
   secudp_uint32   lastRoundTripTime;
   secudp_uint32   lowestRoundTripTime;
   secudp_uint32   lastRoundTripTimeVariance;
   secudp_uint32   highestRoundTripTimeVariance;
   secudp_uint32   roundTripTime;            /**< mean round trip time (RTT), in milliseconds, between sending a reliable packet and receiving its acknowledgement */
   secudp_uint32   roundTripTimeVariance;
   secudp_uint32   mtu;
   secudp_uint32   windowSize;
   secudp_uint32   reliableDataInTransit;
   secudp_uint16   outgoingReliableSequenceNumber;
   SecUdpList      acknowledgements;
   SecUdpList      sentReliableCommands;
   SecUdpList      sentUnreliableCommands;
   SecUdpList      outgoingCommands;
   SecUdpList      dispatchedCommands;
   secudp_uint16   flags;
   secudp_uint16   reserved;
   secudp_uint16   incomingUnsequencedGroup;
   secudp_uint16   outgoingUnsequencedGroup;
   secudp_uint32   unsequencedWindow [SECUDP_PEER_UNSEQUENCED_WINDOW_SIZE / 32]; 
   secudp_uint32   eventData;
   size_t        totalWaitingData;

   SecUdpPeerSecret *secret;
} SecUdpPeer;

/** An SecUdp packet compressor for compressing UDP packets before socket sends or receives.
 */
typedef struct _SecUdpCompressor
{
   /** Context data for the compressor. Must be non-NULL. */
   void * context;
   /** Compresses from inBuffers[0:inBufferCount-1], containing inLimit bytes, to outData, outputting at most outLimit bytes. Should return 0 on failure. */
   size_t (SECUDP_CALLBACK * compress) (void * context, const SecUdpBuffer * inBuffers, size_t inBufferCount, size_t inLimit, secudp_uint8 * outData, size_t outLimit);
   /** Decompresses from inData, containing inLimit bytes, to outData, outputting at most outLimit bytes. Should return 0 on failure. */
   size_t (SECUDP_CALLBACK * decompress) (void * context, const secudp_uint8 * inData, size_t inLimit, secudp_uint8 * outData, size_t outLimit);
   /** Destroys the context when compression is disabled or the host is destroyed. May be NULL. */
   void (SECUDP_CALLBACK * destroy) (void * context);
} SecUdpCompressor;

/** Callback that computes the checksum of the data held in buffers[0:bufferCount-1] */
typedef secudp_uint32 (SECUDP_CALLBACK * SecUdpChecksumCallback) (const SecUdpBuffer * buffers, size_t bufferCount);

/** Callback for intercepting received raw UDP packets. Should return 1 to intercept, 0 to ignore, or -1 to propagate an error. */
typedef int (SECUDP_CALLBACK * SecUdpInterceptCallback) (struct _SecUdpHost * host, struct _SecUdpEvent * event);

typedef struct _SecUdpHostSecret {
  secudp_uint32 privateKey[8];
  secudp_uint32 publicKey[8];
} SecUdpHostSecret;

/** An SecUdp host for communicating with peers.
  *
  * No fields should be modified unless otherwise stated.

    @sa secudp_host_create()
    @sa secudp_host_destroy()
    @sa secudp_host_connect()
    @sa secudp_host_service()
    @sa secudp_host_flush()
    @sa secudp_host_broadcast()
    @sa secudp_host_compress()
    @sa secudp_host_compress_with_range_coder()
    @sa secudp_host_channel_limit()
    @sa secudp_host_bandwidth_limit()
    @sa secudp_host_bandwidth_throttle()
  */
typedef struct _SecUdpHost
{
   SecUdpSocket           socket;
   SecUdpAddress          address;                     /**< Internet address of the host */
   secudp_uint32          incomingBandwidth;           /**< downstream bandwidth of the host */
   secudp_uint32          outgoingBandwidth;           /**< upstream bandwidth of the host */
   secudp_uint32          bandwidthThrottleEpoch;
   secudp_uint32          mtu;
   secudp_uint32          randomSeed;
   int                  recalculateBandwidthLimits;
   SecUdpPeer *           peers;                       /**< array of peers allocated for this host */
   size_t               peerCount;                   /**< number of peers allocated for this host */
   size_t               channelLimit;                /**< maximum number of channels allowed for connected peers */
   secudp_uint32          serviceTime;
   SecUdpList             dispatchQueue;
   int                  continueSending;
   size_t               packetSize;
   secudp_uint16          headerFlags;
   SecUdpProtocol         commands [SECUDP_PROTOCOL_MAXIMUM_PACKET_COMMANDS];
   size_t               commandCount;
   SecUdpBuffer           buffers [SECUDP_BUFFER_MAXIMUM];
   size_t               bufferCount;
   SecUdpChecksumCallback checksum;                    /**< callback the user can set to enable packet checksums for this host */
   SecUdpCompressor       compressor;
   secudp_uint8           packetData [2][SECUDP_PROTOCOL_MAXIMUM_MTU];
   SecUdpAddress          receivedAddress;
   secudp_uint8 *         receivedData;
   size_t               receivedDataLength;
   secudp_uint32          totalSentData;               /**< total data sent, user should reset to 0 as needed to prevent overflow */
   secudp_uint32          totalSentPackets;            /**< total UDP packets sent, user should reset to 0 as needed to prevent overflow */
   secudp_uint32          totalReceivedData;           /**< total data received, user should reset to 0 as needed to prevent overflow */
   secudp_uint32          totalReceivedPackets;        /**< total UDP packets received, user should reset to 0 as needed to prevent overflow */
   SecUdpInterceptCallback intercept;                  /**< callback the user can set to intercept received raw UDP packets */
   size_t               connectedPeers;
   size_t               bandwidthLimitedPeers;
   size_t               duplicatePeers;              /**< optional number of allowed peers from duplicate IPs, defaults to SECUDP_PROTOCOL_MAXIMUM_PEER_ID */
   size_t               maximumPacketSize;           /**< the maximum allowable packet size that may be sent or received on a peer */
   size_t               maximumWaitingData;          /**< the maximum aggregate amount of buffer space a peer may use waiting for packets to be delivered */

   SecUdpHostSecret *secret;
} SecUdpHost;

/**
 * An SecUdp event type, as specified in @ref SecUdpEvent.
 */
typedef enum _SecUdpEventType
{
   /** no event occurred within the specified time limit */
   SECUDP_EVENT_TYPE_NONE       = 0,  

   /** a connection request initiated by secudp_host_connect has completed.  
     * The peer field contains the peer which successfully connected. 
     */
   SECUDP_EVENT_TYPE_CONNECT    = 1,  

   /** a peer has disconnected.  This event is generated on a successful 
     * completion of a disconnect initiated by secudp_peer_disconnect, if 
     * a peer has timed out, or if a connection request intialized by 
     * secudp_host_connect has timed out.  The peer field contains the peer 
     * which disconnected. The data field contains user supplied data 
     * describing the disconnection, or 0, if none is available.
     */
   SECUDP_EVENT_TYPE_DISCONNECT = 2,  

   /** a packet has been received from a peer.  The peer field specifies the
     * peer which sent the packet.  The channelID field specifies the channel
     * number upon which the packet was received.  The packet field contains
     * the packet that was received; this packet must be destroyed with
     * secudp_packet_destroy after use.
     */
   SECUDP_EVENT_TYPE_RECEIVE    = 3
} SecUdpEventType;

/**
 * An SecUdp event as returned by secudp_host_service().
   
   @sa secudp_host_service
 */
typedef struct _SecUdpEvent 
{
   SecUdpEventType        type;      /**< type of the event */
   SecUdpPeer *           peer;      /**< peer that generated a connect, disconnect or receive event */
   secudp_uint8           channelID; /**< channel on the peer that generated the event, if appropriate */
   secudp_uint32          data;      /**< data associated with the event, if appropriate */
   SecUdpPacket *         packet;    /**< packet associated with the event, if appropriate */
} SecUdpEvent;

/** @defgroup global SecUdp global functions
    @{ 
*/

/** 
  Initializes SecUdp globally.  Must be called prior to using any functions in
  SecUdp.
  @returns 0 on success, < 0 on failure
*/
SECUDP_API int secudp_initialize (void);

/** 
  Initializes SecUdp globally and supplies user-overridden callbacks. Must be called prior to using any functions in SecUdp. Do not use secudp_initialize() if you use this variant. Make sure the SecUdpCallbacks structure is zeroed out so that any additional callbacks added in future versions will be properly ignored.

  @param version the constant SECUDP_VERSION should be supplied so SecUdp knows which version of SecUdpCallbacks struct to use
  @param inits user-overridden callbacks where any NULL callbacks will use SecUdp's defaults
  @returns 0 on success, < 0 on failure
*/
SECUDP_API int secudp_initialize_with_callbacks (SecUdpVersion version, const SecUdpCallbacks * inits);

/** 
  Shuts down SecUdp globally.  Should be called when a program that has
  initialized SecUdp exits.
*/
SECUDP_API void secudp_deinitialize (void);

/**
  Gives the linked version of the SecUdp library.
  @returns the version number 
*/
SECUDP_API SecUdpVersion secudp_linked_version (void);

/** @} */

/** @defgroup private SecUdp private implementation functions */

/**
  Returns the wall-time in milliseconds.  Its initial value is unspecified
  unless otherwise set.
  */
SECUDP_API secudp_uint32 secudp_time_get (void);
/**
  Sets the current wall-time in milliseconds.
  */
SECUDP_API void secudp_time_set (secudp_uint32);

/** @defgroup socket SecUdp socket functions
    @{
*/
SECUDP_API SecUdpSocket secudp_socket_create (SecUdpSocketType);
SECUDP_API int        secudp_socket_bind (SecUdpSocket, const SecUdpAddress *);
SECUDP_API int        secudp_socket_get_address (SecUdpSocket, SecUdpAddress *);
SECUDP_API int        secudp_socket_listen (SecUdpSocket, int);
SECUDP_API SecUdpSocket secudp_socket_accept (SecUdpSocket, SecUdpAddress *);
SECUDP_API int        secudp_socket_connect (SecUdpSocket, const SecUdpAddress *);
SECUDP_API int        secudp_socket_send (SecUdpSocket, const SecUdpAddress *, const SecUdpBuffer *, size_t);
SECUDP_API int        secudp_socket_receive (SecUdpSocket, SecUdpAddress *, SecUdpBuffer *, size_t);
SECUDP_API int        secudp_socket_wait (SecUdpSocket, secudp_uint32 *, secudp_uint32);
SECUDP_API int        secudp_socket_set_option (SecUdpSocket, SecUdpSocketOption, int);
SECUDP_API int        secudp_socket_get_option (SecUdpSocket, SecUdpSocketOption, int *);
SECUDP_API int        secudp_socket_shutdown (SecUdpSocket, SecUdpSocketShutdown);
SECUDP_API void       secudp_socket_destroy (SecUdpSocket);
SECUDP_API int        secudp_socketset_select (SecUdpSocket, SecUdpSocketSet *, SecUdpSocketSet *, secudp_uint32);

/** @} */

/** @defgroup Address SecUdp address functions
    @{
*/

/** Attempts to parse the printable form of the IP address in the parameter hostName
    and sets the host field in the address parameter if successful.
    @param address destination to store the parsed IP address
    @param hostName IP address to parse
    @retval 0 on success
    @retval < 0 on failure
    @returns the address of the given hostName in address on success
*/
SECUDP_API int secudp_address_set_host_ip (SecUdpAddress * address, const char * hostName);

/** Attempts to resolve the host named by the parameter hostName and sets
    the host field in the address parameter if successful.
    @param address destination to store resolved address
    @param hostName host name to lookup
    @retval 0 on success
    @retval < 0 on failure
    @returns the address of the given hostName in address on success
*/
SECUDP_API int secudp_address_set_host (SecUdpAddress * address, const char * hostName);

/** Gives the printable form of the IP address specified in the address parameter.
    @param address    address printed
    @param hostName   destination for name, must not be NULL
    @param nameLength maximum length of hostName.
    @returns the null-terminated name of the host in hostName on success
    @retval 0 on success
    @retval < 0 on failure
*/
SECUDP_API int secudp_address_get_host_ip (const SecUdpAddress * address, char * hostName, size_t nameLength);

/** Attempts to do a reverse lookup of the host field in the address parameter.
    @param address    address used for reverse lookup
    @param hostName   destination for name, must not be NULL
    @param nameLength maximum length of hostName.
    @returns the null-terminated name of the host in hostName on success
    @retval 0 on success
    @retval < 0 on failure
*/
SECUDP_API int secudp_address_get_host (const SecUdpAddress * address, char * hostName, size_t nameLength);

/** @} */

SECUDP_API SecUdpPacket * secudp_packet_create (const void *, size_t, secudp_uint32);
SECUDP_API void         secudp_packet_destroy (SecUdpPacket *);
SECUDP_API int          secudp_packet_resize  (SecUdpPacket *, size_t);
SECUDP_API secudp_uint32  secudp_crc32 (const SecUdpBuffer *, size_t);
                
SECUDP_API SecUdpHost * secudp_host_create (const SecUdpAddress *, const SecUdpHostSecret *secret, size_t, size_t, secudp_uint32, secudp_uint32);
SECUDP_API void       secudp_host_destroy (SecUdpHost *);
SECUDP_API SecUdpPeer * secudp_host_connect (SecUdpHost *, const SecUdpAddress *, size_t, secudp_uint32);
SECUDP_API int        secudp_host_check_events (SecUdpHost *, SecUdpEvent *);
SECUDP_API int        secudp_host_service (SecUdpHost *, SecUdpEvent *, secudp_uint32);
SECUDP_API void       secudp_host_flush (SecUdpHost *);
SECUDP_API void       secudp_host_broadcast (SecUdpHost *, secudp_uint8, SecUdpPacket *);
SECUDP_API void       secudp_host_compress (SecUdpHost *, const SecUdpCompressor *);
SECUDP_API int        secudp_host_compress_with_range_coder (SecUdpHost * host);
SECUDP_API void       secudp_host_channel_limit (SecUdpHost *, size_t);
SECUDP_API void       secudp_host_bandwidth_limit (SecUdpHost *, secudp_uint32, secudp_uint32);
extern   void       secudp_host_bandwidth_throttle (SecUdpHost *);
extern  secudp_uint32 secudp_host_random_seed (void);

SECUDP_API int                 secudp_peer_send (SecUdpPeer *, secudp_uint8, SecUdpPacket *);
SECUDP_API SecUdpPacket *        secudp_peer_receive (SecUdpPeer *, secudp_uint8 * channelID);
SECUDP_API void                secudp_peer_ping (SecUdpPeer *);
SECUDP_API void                secudp_peer_ping_interval (SecUdpPeer *, secudp_uint32);
SECUDP_API void                secudp_peer_timeout (SecUdpPeer *, secudp_uint32, secudp_uint32, secudp_uint32);
SECUDP_API void                secudp_peer_reset (SecUdpPeer *);
SECUDP_API void                secudp_peer_disconnect (SecUdpPeer *, secudp_uint32);
SECUDP_API void                secudp_peer_disconnect_now (SecUdpPeer *, secudp_uint32);
SECUDP_API void                secudp_peer_disconnect_later (SecUdpPeer *, secudp_uint32);
SECUDP_API void                secudp_peer_throttle_configure (SecUdpPeer *, secudp_uint32, secudp_uint32, secudp_uint32);
extern int                   secudp_peer_throttle (SecUdpPeer *, secudp_uint32);
extern void                  secudp_peer_reset_queues (SecUdpPeer *);
extern void                  secudp_peer_setup_outgoing_command (SecUdpPeer *, SecUdpOutgoingCommand *);
extern SecUdpOutgoingCommand * secudp_peer_queue_outgoing_command (SecUdpPeer *, const SecUdpProtocol *, SecUdpPacket *, secudp_uint32, secudp_uint16);
extern SecUdpIncomingCommand * secudp_peer_queue_incoming_command (SecUdpPeer *, const SecUdpProtocol *, const void *, size_t, secudp_uint32, secudp_uint32);
extern SecUdpAcknowledgement * secudp_peer_queue_acknowledgement (SecUdpPeer *, const SecUdpProtocol *, secudp_uint16);
extern void                  secudp_peer_dispatch_incoming_unreliable_commands (SecUdpPeer *, SecUdpChannel *, SecUdpIncomingCommand *);
extern void                  secudp_peer_dispatch_incoming_reliable_commands (SecUdpPeer *, SecUdpChannel *, SecUdpIncomingCommand *);
extern void                  secudp_peer_on_connect (SecUdpPeer *);
extern void                  secudp_peer_on_disconnect (SecUdpPeer *);

SECUDP_API void * secudp_range_coder_create (void);
SECUDP_API void   secudp_range_coder_destroy (void *);
SECUDP_API size_t secudp_range_coder_compress (void *, const SecUdpBuffer *, size_t, size_t, secudp_uint8 *, size_t);
SECUDP_API size_t secudp_range_coder_decompress (void *, const secudp_uint8 *, size_t, secudp_uint8 *, size_t);
   
extern size_t secudp_protocol_command_size (secudp_uint8);

#ifdef __cplusplus
}
#endif

#endif /* __SECUDP_SECUDP_H__ */

