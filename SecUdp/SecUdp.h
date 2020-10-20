#ifndef SECUDP_H
#define SECUDP_H

#include <enet/enet.h>

typedef struct SecUdpPeerSecret {
  enet_uint32 mac_key[8];
  enet_uint32 chacha_key[8]; 
} SecUdpPeerSecret;

typedef struct SecUdpHostSecret {
  enet_uint32 public_key[8];
  enet_uint32 private_key[8]; 
} SecUdpHostSecret;

typedef struct SecUdpHost {
   ENetSocket           socket;
   ENetAddress          address;                     
   enet_uint32          incomingBandwidth;           
   enet_uint32          outgoingBandwidth;           
   enet_uint32          bandwidthThrottleEpoch;
   enet_uint32          mtu;
   enet_uint32          randomSeed;
   int                  recalculateBandwidthLimits;
   ENetPeer *           peers;                       
   size_t               peerCount;                   
   size_t               channelLimit;                
   enet_uint32          serviceTime;
   ENetList             dispatchQueue;
   int                  continueSending;
   size_t               packetSize;
   enet_uint16          headerFlags;
   ENetProtocol         commands [ENET_PROTOCOL_MAXIMUM_PACKET_COMMANDS];
   size_t               commandCount;
   ENetBuffer           buffers [ENET_BUFFER_MAXIMUM];
   size_t               bufferCount;
   ENetChecksumCallback checksum;                    
   ENetCompressor       compressor;
   enet_uint8           packetData [2][ENET_PROTOCOL_MAXIMUM_MTU];
   ENetAddress          receivedAddress;
   enet_uint8 *         receivedData;
   size_t               receivedDataLength;
   enet_uint32          totalSentData;               
   enet_uint32          totalSentPackets;            
   enet_uint32          totalReceivedData;           
   enet_uint32          totalReceivedPackets;        
   ENetInterceptCallback intercept;                  
   size_t               connectedPeers;
   size_t               bandwidthLimitedPeers;
   size_t               duplicatePeers;              
   size_t               maximumPacketSize;           
   size_t               maximumWaitingData;          

   SecUdpHostSecret *secret;
} SecUdpHost;

typedef struct SecUdpData {
  SecUdpPeerSecret secret;
  enet_uint32 counter;
  void *data;
} SecUdpData;

typedef struct SecUdpPeer {
   ENetListNode  dispatchList;
   struct _ENetHost * host;
   enet_uint16   outgoingPeerID;
   enet_uint16   incomingPeerID;
   enet_uint32   connectID;
   enet_uint8    outgoingSessionID;
   enet_uint8    incomingSessionID;
   ENetAddress   address;            
   SecUdpData    *secudp_data;              
   ENetPeerState state;
   ENetChannel * channels;
   size_t        channelCount;       
   enet_uint32   incomingBandwidth;  
   enet_uint32   outgoingBandwidth;  
   enet_uint32   incomingBandwidthThrottleEpoch;
   enet_uint32   outgoingBandwidthThrottleEpoch;
   enet_uint32   incomingDataTotal;
   enet_uint32   outgoingDataTotal;
   enet_uint32   lastSendTime;
   enet_uint32   lastReceiveTime;
   enet_uint32   nextTimeout;
   enet_uint32   earliestTimeout;
   enet_uint32   packetLossEpoch;
   enet_uint32   packetsSent;
   enet_uint32   packetsLost;
   enet_uint32   packetLoss;          
   enet_uint32   packetLossVariance;
   enet_uint32   packetThrottle;
   enet_uint32   packetThrottleLimit;
   enet_uint32   packetThrottleCounter;
   enet_uint32   packetThrottleEpoch;
   enet_uint32   packetThrottleAcceleration;
   enet_uint32   packetThrottleDeceleration;
   enet_uint32   packetThrottleInterval;
   enet_uint32   pingInterval;
   enet_uint32   timeoutLimit;
   enet_uint32   timeoutMinimum;
   enet_uint32   timeoutMaximum;
   enet_uint32   lastRoundTripTime;
   enet_uint32   lowestRoundTripTime;
   enet_uint32   lastRoundTripTimeVariance;
   enet_uint32   highestRoundTripTimeVariance;
   enet_uint32   roundTripTime;            
   enet_uint32   roundTripTimeVariance;
   enet_uint32   mtu;
   enet_uint32   windowSize;
   enet_uint32   reliableDataInTransit;
   enet_uint16   outgoingReliableSequenceNumber;
   ENetList      acknowledgements;
   ENetList      sentReliableCommands;
   ENetList      sentUnreliableCommands;
   ENetList      outgoingCommands;
   ENetList      dispatchedCommands;
   enet_uint16   flags;
   enet_uint16   reserved;
   enet_uint16   incomingUnsequencedGroup;
   enet_uint16   outgoingUnsequencedGroup;
   enet_uint32   unsequencedWindow [ENET_PEER_UNSEQUENCED_WINDOW_SIZE / 32];
   enet_uint32   eventData;
   size_t        totalWaitingData;
} SecUdpPeer;


typedef enum SecUdpEventType {
  SECUDP_EVENT_TYPE_NONE = ENET_EVENT_TYPE_NONE,
  SECUDP_EVENT_TYPE_CONNECT = ENET_EVENT_TYPE_CONNECT,
  SECUDP_EVENT_TYPE_DISCONNECT = ENET_EVENT_TYPE_DISCONNECT,
  SECUDP_EVENT_TYPE_RECEIVE = ENET_EVENT_TYPE_RECEIVE,
  SECUDP_EVENT_TYPE_HANDSHAKING
} SecUdpEventType;


typedef struct SecUdpPacket {
   size_t                   referenceCount;  
   enet_uint32              flags;           
   enet_uint8 *             data;            
   size_t                   dataLength;      
   ENetPacketFreeCallback   freeCallback;    
   void *                   userData;        
} SecUdpPacket;

typedef struct SecUdpPacketHeader {
  enet_uint32 timestamp;
  enet_uint32 random_nonce;
  enet_uint32 counter; 
} SecUdpPacketHeader;

typedef struct SecUdpEvent {
  SecUdpEventType        type;      
  SecUdpPeer *           peer;      
  enet_uint8             channelID; 
  enet_uint32            data;      
  SecUdpPacket *         packet;    
} SecUdpEvent;

typedef struct SecUdpAddress {
  enet_uint32 host;
  enet_uint16 port;
} SecUdpAddress;
  
SecUdpHost *secudp_host_create(
  const SecUdpAddress *address, const SecUdpHostSecret *secret,
  size_t peerCount, size_t channelLimit, 
  enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth);

void secudp_host_destroy(SecUdpHost *host);

SecUdpPeer *secudp_host_connect(
  SecUdpHost *host, const SecUdpAddress *address,
  size_t channelCount, enet_uint32 data);

int secudp_host_service(
  SecUdpHost *host, SecUdpEvent *event, 
  enet_uint32 timeout);

int secudp_initialize();

#endif

