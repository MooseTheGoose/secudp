/** 
 @file host.c
 @brief SecUdp host management functions
*/
#define SECUDP_BUILDING_LIB 1
#include <string.h>
#include "SecUdp/SecUdp.h"

/** @defgroup host SecUdp host functions
    @{
*/

/** Creates a host for communicating to peers.  

    @param address   the address at which other peers may connect to this host.  If NULL, then no peers may connect to the host.
    @param peerCount the maximum number of peers that should be allocated for the host.
    @param channelLimit the maximum number of channels allowed; if 0, then this is equivalent to SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT
    @param incomingBandwidth downstream bandwidth of the host in bytes/second; if 0, SecUdp will assume unlimited bandwidth.
    @param outgoingBandwidth upstream bandwidth of the host in bytes/second; if 0, SecUdp will assume unlimited bandwidth.

    @returns the host on success and NULL on failure

    @remarks SecUdp will strategically drop packets on specific sides of a connection between hosts
    to ensure the host's bandwidth is not overwhelmed.  The bandwidth parameters also determine
    the window size of a connection which limits the amount of reliable packets that may be in transit
    at any given time.
*/
SecUdpHost *
secudp_host_create (const SecUdpAddress * address, size_t peerCount, size_t channelLimit, secudp_uint32 incomingBandwidth, secudp_uint32 outgoingBandwidth)
{
    SecUdpHost * host;
    SecUdpPeer * currentPeer;

    if (peerCount > SECUDP_PROTOCOL_MAXIMUM_PEER_ID)
      return NULL;

    host = (SecUdpHost *) secudp_malloc (sizeof (SecUdpHost));
    if (host == NULL)
      return NULL;
    memset (host, 0, sizeof (SecUdpHost));

    host -> peers = (SecUdpPeer *) secudp_malloc (peerCount * sizeof (SecUdpPeer));
    if (host -> peers == NULL)
    {
       secudp_free (host);

       return NULL;
    }
    memset (host -> peers, 0, peerCount * sizeof (SecUdpPeer));

    host -> socket = secudp_socket_create (SECUDP_SOCKET_TYPE_DATAGRAM);
    if (host -> socket == SECUDP_SOCKET_NULL || (address != NULL && secudp_socket_bind (host -> socket, address) < 0))
    {
       if (host -> socket != SECUDP_SOCKET_NULL)
         secudp_socket_destroy (host -> socket);

       secudp_free (host -> peers);
       secudp_free (host);

       return NULL;
    }

    secudp_socket_set_option (host -> socket, SECUDP_SOCKOPT_NONBLOCK, 1);
    secudp_socket_set_option (host -> socket, SECUDP_SOCKOPT_BROADCAST, 1);
    secudp_socket_set_option (host -> socket, SECUDP_SOCKOPT_RCVBUF, SECUDP_HOST_RECEIVE_BUFFER_SIZE);
    secudp_socket_set_option (host -> socket, SECUDP_SOCKOPT_SNDBUF, SECUDP_HOST_SEND_BUFFER_SIZE);

    if (address != NULL && secudp_socket_get_address (host -> socket, & host -> address) < 0)   
      host -> address = * address;

    if (! channelLimit || channelLimit > SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
      channelLimit = SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
    else
    if (channelLimit < SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT)
      channelLimit = SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT;

    host -> randomSeed = (secudp_uint32) (size_t) host;
    host -> randomSeed += secudp_host_random_seed ();
    host -> randomSeed = (host -> randomSeed << 16) | (host -> randomSeed >> 16);
    host -> channelLimit = channelLimit;
    host -> incomingBandwidth = incomingBandwidth;
    host -> outgoingBandwidth = outgoingBandwidth;
    host -> bandwidthThrottleEpoch = 0;
    host -> recalculateBandwidthLimits = 0;
    host -> mtu = SECUDP_HOST_DEFAULT_MTU;
    host -> peerCount = peerCount;
    host -> commandCount = 0;
    host -> bufferCount = 0;
    host -> checksum = NULL;
    host -> receivedAddress.host = SECUDP_HOST_ANY;
    host -> receivedAddress.port = 0;
    host -> receivedData = NULL;
    host -> receivedDataLength = 0;
     
    host -> totalSentData = 0;
    host -> totalSentPackets = 0;
    host -> totalReceivedData = 0;
    host -> totalReceivedPackets = 0;

    host -> connectedPeers = 0;
    host -> bandwidthLimitedPeers = 0;
    host -> duplicatePeers = SECUDP_PROTOCOL_MAXIMUM_PEER_ID;
    host -> maximumPacketSize = SECUDP_HOST_DEFAULT_MAXIMUM_PACKET_SIZE;
    host -> maximumWaitingData = SECUDP_HOST_DEFAULT_MAXIMUM_WAITING_DATA;

    host -> compressor.context = NULL;
    host -> compressor.compress = NULL;
    host -> compressor.decompress = NULL;
    host -> compressor.destroy = NULL;

    host -> intercept = NULL;

    secudp_list_clear (& host -> dispatchQueue);

    for (currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
       currentPeer -> host = host;
       currentPeer -> incomingPeerID = currentPeer - host -> peers;
       currentPeer -> outgoingSessionID = currentPeer -> incomingSessionID = 0xFF;
       currentPeer -> data = NULL;

       secudp_list_clear (& currentPeer -> acknowledgements);
       secudp_list_clear (& currentPeer -> sentReliableCommands);
       secudp_list_clear (& currentPeer -> sentUnreliableCommands);
       secudp_list_clear (& currentPeer -> outgoingCommands);
       secudp_list_clear (& currentPeer -> dispatchedCommands);

       secudp_peer_reset (currentPeer);
    }

    return host;
}

/** Destroys the host and all resources associated with it.
    @param host pointer to the host to destroy
*/
void
secudp_host_destroy (SecUdpHost * host)
{
    SecUdpPeer * currentPeer;

    if (host == NULL)
      return;

    secudp_socket_destroy (host -> socket);

    for (currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
       secudp_peer_reset (currentPeer);
    }

    if (host -> compressor.context != NULL && host -> compressor.destroy)
      (* host -> compressor.destroy) (host -> compressor.context);

    secudp_free (host -> peers);
    secudp_free (host);
}

/** Initiates a connection to a foreign host.
    @param host host seeking the connection
    @param address destination for the connection
    @param channelCount number of channels to allocate
    @param data user data supplied to the receiving host 
    @returns a peer representing the foreign host on success, NULL on failure
    @remarks The peer returned will have not completed the connection until secudp_host_service()
    notifies of an SECUDP_EVENT_TYPE_CONNECT event for the peer.
*/
SecUdpPeer *
secudp_host_connect (SecUdpHost * host, const SecUdpAddress * address, size_t channelCount, secudp_uint32 data)
{
    SecUdpPeer * currentPeer;
    SecUdpChannel * channel;
    SecUdpProtocol command;

    if (channelCount < SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT)
      channelCount = SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT;
    else
    if (channelCount > SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
      channelCount = SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT;

    for (currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
       if (currentPeer -> state == SECUDP_PEER_STATE_DISCONNECTED)
         break;
    }

    if (currentPeer >= & host -> peers [host -> peerCount])
      return NULL;

    currentPeer -> channels = (SecUdpChannel *) secudp_malloc (channelCount * sizeof (SecUdpChannel));
    if (currentPeer -> channels == NULL)
      return NULL;
    currentPeer -> channelCount = channelCount;
    currentPeer -> state = SECUDP_PEER_STATE_CONNECTING;
    currentPeer -> address = * address;
    currentPeer -> connectID = ++ host -> randomSeed;

    if (host -> outgoingBandwidth == 0)
      currentPeer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
      currentPeer -> windowSize = (host -> outgoingBandwidth /
                                    SECUDP_PEER_WINDOW_SIZE_SCALE) * 
                                      SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (currentPeer -> windowSize < SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE)
      currentPeer -> windowSize = SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
    if (currentPeer -> windowSize > SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE)
      currentPeer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
         
    for (channel = currentPeer -> channels;
         channel < & currentPeer -> channels [channelCount];
         ++ channel)
    {
        channel -> outgoingReliableSequenceNumber = 0;
        channel -> outgoingUnreliableSequenceNumber = 0;
        channel -> incomingReliableSequenceNumber = 0;
        channel -> incomingUnreliableSequenceNumber = 0;

        secudp_list_clear (& channel -> incomingReliableCommands);
        secudp_list_clear (& channel -> incomingUnreliableCommands);

        channel -> usedReliableWindows = 0;
        memset (channel -> reliableWindows, 0, sizeof (channel -> reliableWindows));
    }
        
    command.header.command = SECUDP_PROTOCOL_COMMAND_CONNECT | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID = 0xFF;
    command.connect.outgoingPeerID = SECUDP_HOST_TO_NET_16 (currentPeer -> incomingPeerID);
    command.connect.incomingSessionID = currentPeer -> incomingSessionID;
    command.connect.outgoingSessionID = currentPeer -> outgoingSessionID;
    command.connect.mtu = SECUDP_HOST_TO_NET_32 (currentPeer -> mtu);
    command.connect.windowSize = SECUDP_HOST_TO_NET_32 (currentPeer -> windowSize);
    command.connect.channelCount = SECUDP_HOST_TO_NET_32 (channelCount);
    command.connect.incomingBandwidth = SECUDP_HOST_TO_NET_32 (host -> incomingBandwidth);
    command.connect.outgoingBandwidth = SECUDP_HOST_TO_NET_32 (host -> outgoingBandwidth);
    command.connect.packetThrottleInterval = SECUDP_HOST_TO_NET_32 (currentPeer -> packetThrottleInterval);
    command.connect.packetThrottleAcceleration = SECUDP_HOST_TO_NET_32 (currentPeer -> packetThrottleAcceleration);
    command.connect.packetThrottleDeceleration = SECUDP_HOST_TO_NET_32 (currentPeer -> packetThrottleDeceleration);
    command.connect.connectID = currentPeer -> connectID;
    command.connect.data = SECUDP_HOST_TO_NET_32 (data);
 
    secudp_peer_queue_outgoing_command (currentPeer, & command, NULL, 0, 0);

    return currentPeer;
}

/** Queues a packet to be sent to all peers associated with the host.
    @param host host on which to broadcast the packet
    @param channelID channel on which to broadcast
    @param packet packet to broadcast
*/
void
secudp_host_broadcast (SecUdpHost * host, secudp_uint8 channelID, SecUdpPacket * packet)
{
    SecUdpPeer * currentPeer;

    for (currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
       if (currentPeer -> state != SECUDP_PEER_STATE_CONNECTED)
         continue;

       secudp_peer_send (currentPeer, channelID, packet);
    }

    if (packet -> referenceCount == 0)
      secudp_packet_destroy (packet);
}

/** Sets the packet compressor the host should use to compress and decompress packets.
    @param host host to enable or disable compression for
    @param compressor callbacks for for the packet compressor; if NULL, then compression is disabled
*/
void
secudp_host_compress (SecUdpHost * host, const SecUdpCompressor * compressor)
{
    if (host -> compressor.context != NULL && host -> compressor.destroy)
      (* host -> compressor.destroy) (host -> compressor.context);

    if (compressor)
      host -> compressor = * compressor;
    else
      host -> compressor.context = NULL;
}

/** Limits the maximum allowed channels of future incoming connections.
    @param host host to limit
    @param channelLimit the maximum number of channels allowed; if 0, then this is equivalent to SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT
*/
void
secudp_host_channel_limit (SecUdpHost * host, size_t channelLimit)
{
    if (! channelLimit || channelLimit > SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
      channelLimit = SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT;
    else
    if (channelLimit < SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT)
      channelLimit = SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT;

    host -> channelLimit = channelLimit;
}


/** Adjusts the bandwidth limits of a host.
    @param host host to adjust
    @param incomingBandwidth new incoming bandwidth
    @param outgoingBandwidth new outgoing bandwidth
    @remarks the incoming and outgoing bandwidth parameters are identical in function to those
    specified in secudp_host_create().
*/
void
secudp_host_bandwidth_limit (SecUdpHost * host, secudp_uint32 incomingBandwidth, secudp_uint32 outgoingBandwidth)
{
    host -> incomingBandwidth = incomingBandwidth;
    host -> outgoingBandwidth = outgoingBandwidth;
    host -> recalculateBandwidthLimits = 1;
}

void
secudp_host_bandwidth_throttle (SecUdpHost * host)
{
    secudp_uint32 timeCurrent = secudp_time_get (),
           elapsedTime = timeCurrent - host -> bandwidthThrottleEpoch,
           peersRemaining = (secudp_uint32) host -> connectedPeers,
           dataTotal = ~0,
           bandwidth = ~0,
           throttle = 0,
           bandwidthLimit = 0;
    int needsAdjustment = host -> bandwidthLimitedPeers > 0 ? 1 : 0;
    SecUdpPeer * peer;
    SecUdpProtocol command;

    if (elapsedTime < SECUDP_HOST_BANDWIDTH_THROTTLE_INTERVAL)
      return;

    host -> bandwidthThrottleEpoch = timeCurrent;

    if (peersRemaining == 0)
      return;

    if (host -> outgoingBandwidth != 0)
    {
        dataTotal = 0;
        bandwidth = (host -> outgoingBandwidth * elapsedTime) / 1000;

        for (peer = host -> peers;
             peer < & host -> peers [host -> peerCount];
            ++ peer)
        {
            if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
              continue;

            dataTotal += peer -> outgoingDataTotal;
        }
    }

    while (peersRemaining > 0 && needsAdjustment != 0)
    {
        needsAdjustment = 0;
        
        if (dataTotal <= bandwidth)
          throttle = SECUDP_PEER_PACKET_THROTTLE_SCALE;
        else
          throttle = (bandwidth * SECUDP_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

        for (peer = host -> peers;
             peer < & host -> peers [host -> peerCount];
             ++ peer)
        {
            secudp_uint32 peerBandwidth;
            
            if ((peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER) ||
                peer -> incomingBandwidth == 0 ||
                peer -> outgoingBandwidthThrottleEpoch == timeCurrent)
              continue;

            peerBandwidth = (peer -> incomingBandwidth * elapsedTime) / 1000;
            if ((throttle * peer -> outgoingDataTotal) / SECUDP_PEER_PACKET_THROTTLE_SCALE <= peerBandwidth)
              continue;

            peer -> packetThrottleLimit = (peerBandwidth * 
                                            SECUDP_PEER_PACKET_THROTTLE_SCALE) / peer -> outgoingDataTotal;
            
            if (peer -> packetThrottleLimit == 0)
              peer -> packetThrottleLimit = 1;
            
            if (peer -> packetThrottle > peer -> packetThrottleLimit)
              peer -> packetThrottle = peer -> packetThrottleLimit;

            peer -> outgoingBandwidthThrottleEpoch = timeCurrent;

            peer -> incomingDataTotal = 0;
            peer -> outgoingDataTotal = 0;

            needsAdjustment = 1;
            -- peersRemaining;
            bandwidth -= peerBandwidth;
            dataTotal -= peerBandwidth;
        }
    }

    if (peersRemaining > 0)
    {
        if (dataTotal <= bandwidth)
          throttle = SECUDP_PEER_PACKET_THROTTLE_SCALE;
        else
          throttle = (bandwidth * SECUDP_PEER_PACKET_THROTTLE_SCALE) / dataTotal;

        for (peer = host -> peers;
             peer < & host -> peers [host -> peerCount];
             ++ peer)
        {
            if ((peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER) ||
                peer -> outgoingBandwidthThrottleEpoch == timeCurrent)
              continue;

            peer -> packetThrottleLimit = throttle;

            if (peer -> packetThrottle > peer -> packetThrottleLimit)
              peer -> packetThrottle = peer -> packetThrottleLimit;

            peer -> incomingDataTotal = 0;
            peer -> outgoingDataTotal = 0;
        }
    }

    if (host -> recalculateBandwidthLimits)
    {
       host -> recalculateBandwidthLimits = 0;

       peersRemaining = (secudp_uint32) host -> connectedPeers;
       bandwidth = host -> incomingBandwidth;
       needsAdjustment = 1;

       if (bandwidth == 0)
         bandwidthLimit = 0;
       else
       while (peersRemaining > 0 && needsAdjustment != 0)
       {
           needsAdjustment = 0;
           bandwidthLimit = bandwidth / peersRemaining;

           for (peer = host -> peers;
                peer < & host -> peers [host -> peerCount];
                ++ peer)
           {
               if ((peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER) ||
                   peer -> incomingBandwidthThrottleEpoch == timeCurrent)
                 continue;

               if (peer -> outgoingBandwidth > 0 &&
                   peer -> outgoingBandwidth >= bandwidthLimit)
                 continue;

               peer -> incomingBandwidthThrottleEpoch = timeCurrent;
 
               needsAdjustment = 1;
               -- peersRemaining;
               bandwidth -= peer -> outgoingBandwidth;
           }
       }

       for (peer = host -> peers;
            peer < & host -> peers [host -> peerCount];
            ++ peer)
       {
           if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
             continue;

           command.header.command = SECUDP_PROTOCOL_COMMAND_BANDWIDTH_LIMIT | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
           command.header.channelID = 0xFF;
           command.bandwidthLimit.outgoingBandwidth = SECUDP_HOST_TO_NET_32 (host -> outgoingBandwidth);

           if (peer -> incomingBandwidthThrottleEpoch == timeCurrent)
             command.bandwidthLimit.incomingBandwidth = SECUDP_HOST_TO_NET_32 (peer -> outgoingBandwidth);
           else
             command.bandwidthLimit.incomingBandwidth = SECUDP_HOST_TO_NET_32 (bandwidthLimit);

           secudp_peer_queue_outgoing_command (peer, & command, NULL, 0, 0);
       } 
    }
}
    
/** @} */
