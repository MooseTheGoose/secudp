/** 
 @file  peer.c
 @brief SecUdp peer management functions
*/
#include <string.h>
#define SECUDP_BUILDING_LIB 1
#include "secudp/secudp.h"
#include "secudp/crypto.h"

/** @defgroup peer SecUdp peer functions 
    @{
*/

/** Configures throttle parameter for a peer.

    Unreliable packets are dropped by SecUdp in response to the varying conditions
    of the Internet connection to the peer.  The throttle represents a probability
    that an unreliable packet should not be dropped and thus sent by SecUdp to the peer.
    The lowest mean round trip time from the sending of a reliable packet to the
    receipt of its acknowledgement is measured over an amount of time specified by
    the interval parameter in milliseconds.  If a measured round trip time happens to
    be significantly less than the mean round trip time measured over the interval, 
    then the throttle probability is increased to allow more traffic by an amount
    specified in the acceleration parameter, which is a ratio to the SECUDP_PEER_PACKET_THROTTLE_SCALE
    constant.  If a measured round trip time happens to be significantly greater than
    the mean round trip time measured over the interval, then the throttle probability
    is decreased to limit traffic by an amount specified in the deceleration parameter, which
    is a ratio to the SECUDP_PEER_PACKET_THROTTLE_SCALE constant.  When the throttle has
    a value of SECUDP_PEER_PACKET_THROTTLE_SCALE, no unreliable packets are dropped by 
    SecUdp, and so 100% of all unreliable packets will be sent.  When the throttle has a
    value of 0, all unreliable packets are dropped by SecUdp, and so 0% of all unreliable
    packets will be sent.  Intermediate values for the throttle represent intermediate
    probabilities between 0% and 100% of unreliable packets being sent.  The bandwidth
    limits of the local and foreign hosts are taken into account to determine a 
    sensible limit for the throttle probability above which it should not raise even in
    the best of conditions.

    @param peer peer to configure 
    @param interval interval, in milliseconds, over which to measure lowest mean RTT; the default value is SECUDP_PEER_PACKET_THROTTLE_INTERVAL.
    @param acceleration rate at which to increase the throttle probability as mean RTT declines
    @param deceleration rate at which to decrease the throttle probability as mean RTT increases
*/
void
secudp_peer_throttle_configure (SecUdpPeer * peer, secudp_uint32 interval, secudp_uint32 acceleration, secudp_uint32 deceleration)
{
    SecUdpProtocol command;

    peer -> packetThrottleInterval = interval;
    peer -> packetThrottleAcceleration = acceleration;
    peer -> packetThrottleDeceleration = deceleration;

    command.header.command = SECUDP_PROTOCOL_COMMAND_THROTTLE_CONFIGURE | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID = 0xFF;

    command.throttleConfigure.packetThrottleInterval = SECUDP_HOST_TO_NET_32 (interval);
    command.throttleConfigure.packetThrottleAcceleration = SECUDP_HOST_TO_NET_32 (acceleration);
    command.throttleConfigure.packetThrottleDeceleration = SECUDP_HOST_TO_NET_32 (deceleration);

    secudp_peer_queue_outgoing_command (peer, & command, NULL, 0, 0);
}

int
secudp_peer_throttle (SecUdpPeer * peer, secudp_uint32 rtt)
{
    if (peer -> lastRoundTripTime <= peer -> lastRoundTripTimeVariance)
    {
        peer -> packetThrottle = peer -> packetThrottleLimit;
    }
    else
    if (rtt <= peer -> lastRoundTripTime)
    {
        peer -> packetThrottle += peer -> packetThrottleAcceleration;

        if (peer -> packetThrottle > peer -> packetThrottleLimit)
          peer -> packetThrottle = peer -> packetThrottleLimit;

        return 1;
    }
    else
    if (rtt > peer -> lastRoundTripTime + 2 * peer -> lastRoundTripTimeVariance)
    {
        if (peer -> packetThrottle > peer -> packetThrottleDeceleration)
          peer -> packetThrottle -= peer -> packetThrottleDeceleration;
        else
          peer -> packetThrottle = 0;

        return -1;
    }

    return 0;
}

/** Queues a packet to be sent.
    @param peer destination for the packet
    @param channelID channel on which to send
    @param packet packet to send
    @retval 0 on success
    @retval < 0 on failure
*/
int
secudp_peer_send (SecUdpPeer * peer, secudp_uint8 channelID, SecUdpPacket * packet)
{
   SecUdpChannel * channel = & peer -> channels [channelID];
   SecUdpProtocol command;
   size_t fragmentLength;
   secudp_uint8 *ciphertext;
   secudp_uint8 *nonce;
   secudp_uint8 *mac;

   packet -> cipherLength = packet -> dataLength + SECUDP_NONCEBYTES + SECUDP_MACBYTES;
   if(packet -> cipherLength < packet -> dataLength)
     return -1;

   /*
    *  Encrypt the packet data. Special step not in ENet.
    */
   ciphertext = (secudp_uint8 *) secudp_malloc(packet -> cipherLength);
   if(ciphertext == NULL)
     return -1;
   nonce = ciphertext + packet -> dataLength;
   mac = nonce + SECUDP_NONCEBYTES;
   secudp_random(nonce, SECUDP_NONCEBYTES);
   secudp_peer_encrypt(ciphertext, mac, packet -> data, packet -> dataLength, nonce, peer -> secret -> sessionPair.sendKey);
   packet -> ciphertext = ciphertext;

   if (peer -> state != SECUDP_PEER_STATE_CONNECTED ||
       channelID >= peer -> channelCount ||
       packet -> dataLength > peer -> host -> maximumPacketSize)
     return -1;

   fragmentLength = peer -> mtu - sizeof (SecUdpProtocolHeader) - sizeof (SecUdpProtocolSendFragment);
   if (peer -> host -> checksum != NULL)
     fragmentLength -= sizeof(secudp_uint32);

   if (packet -> cipherLength > fragmentLength)
   {
      secudp_uint32 fragmentCount = (packet -> cipherLength + fragmentLength - 1) / fragmentLength,
             fragmentNumber,
             fragmentOffset;
      secudp_uint8 commandNumber;
      secudp_uint16 startSequenceNumber; 
      SecUdpList fragments;
      SecUdpOutgoingCommand * fragment;

      if (fragmentCount > SECUDP_PROTOCOL_MAXIMUM_FRAGMENT_COUNT)
        return -1;

      if ((packet -> flags & (SECUDP_PACKET_FLAG_RELIABLE | SECUDP_PACKET_FLAG_UNRELIABLE_FRAGMENT)) == SECUDP_PACKET_FLAG_UNRELIABLE_FRAGMENT &&
          channel -> outgoingUnreliableSequenceNumber < 0xFFFF)
      {
         commandNumber = SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT;
         startSequenceNumber = SECUDP_HOST_TO_NET_16 (channel -> outgoingUnreliableSequenceNumber + 1);
      }
      else
      {
         commandNumber = SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
         startSequenceNumber = SECUDP_HOST_TO_NET_16 (channel -> outgoingReliableSequenceNumber + 1);
      }
        
      secudp_list_clear (& fragments);

      for (fragmentNumber = 0,
             fragmentOffset = 0;
           fragmentOffset < packet -> cipherLength;
           ++ fragmentNumber,
             fragmentOffset += fragmentLength)
      {
         if (packet -> cipherLength - fragmentOffset < fragmentLength)
           fragmentLength = packet -> cipherLength - fragmentOffset;

         fragment = (SecUdpOutgoingCommand *) secudp_malloc (sizeof (SecUdpOutgoingCommand));
         if (fragment == NULL)
         {
            while (! secudp_list_empty (& fragments))
            {
               fragment = (SecUdpOutgoingCommand *) secudp_list_remove (secudp_list_begin (& fragments));
               
               secudp_free (fragment);
            }
            
            return -1;
         }
         
         fragment -> fragmentOffset = fragmentOffset;
         fragment -> fragmentLength = fragmentLength;
         fragment -> packet = packet;
         fragment -> command.header.command = commandNumber;
         fragment -> command.header.channelID = channelID;
         fragment -> command.sendFragment.startSequenceNumber = startSequenceNumber;
         fragment -> command.sendFragment.dataLength = SECUDP_HOST_TO_NET_16 (fragmentLength);
         fragment -> command.sendFragment.fragmentCount = SECUDP_HOST_TO_NET_32 (fragmentCount);
         fragment -> command.sendFragment.fragmentNumber = SECUDP_HOST_TO_NET_32 (fragmentNumber);
         fragment -> command.sendFragment.totalLength = SECUDP_HOST_TO_NET_32 (packet -> cipherLength);
         fragment -> command.sendFragment.fragmentOffset = SECUDP_NET_TO_HOST_32 (fragmentOffset);
        
         secudp_list_insert (secudp_list_end (& fragments), fragment);
      }

      packet -> referenceCount += fragmentNumber;

      while (! secudp_list_empty (& fragments))
      {
         fragment = (SecUdpOutgoingCommand *) secudp_list_remove (secudp_list_begin (& fragments));
 
         secudp_peer_setup_outgoing_command (peer, fragment);
      }

      return 0;
   }

   command.header.channelID = channelID;

   if ((packet -> flags & (SECUDP_PACKET_FLAG_RELIABLE | SECUDP_PACKET_FLAG_UNSEQUENCED)) == SECUDP_PACKET_FLAG_UNSEQUENCED)
   {
      command.header.command = SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED | SECUDP_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;
      command.sendUnsequenced.dataLength = SECUDP_HOST_TO_NET_16 (packet -> cipherLength);
   }
   else 
   if (packet -> flags & SECUDP_PACKET_FLAG_RELIABLE || channel -> outgoingUnreliableSequenceNumber >= 0xFFFF)
   {
      command.header.command = SECUDP_PROTOCOL_COMMAND_SEND_RELIABLE | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
      command.sendReliable.dataLength = SECUDP_HOST_TO_NET_16 (packet -> cipherLength);
   }
   else
   {
      command.header.command = SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE;
      command.sendUnreliable.dataLength = SECUDP_HOST_TO_NET_16 (packet -> cipherLength);
   }

   if (secudp_peer_queue_outgoing_command (peer, & command, packet, 0, packet -> cipherLength) == NULL)
     return -1;

   return 0;
}

/** Attempts to dequeue any incoming queued packet.
    @param peer peer to dequeue packets from
    @param channelID holds the channel ID of the channel the packet was received on success
    @returns a pointer to the packet, or NULL if there are no available incoming queued packets
*/
SecUdpPacket *
secudp_peer_receive (SecUdpPeer * peer, secudp_uint8 * channelID)
{
   SecUdpIncomingCommand * incomingCommand;
   SecUdpPacket * packet;
   secudp_uint8 * data;
   secudp_uint8 * ciphertext;
   size_t dataLength;
   size_t cipherLength;
   secudp_uint8 * mac;
   secudp_uint8 * nonce;
   
   if (secudp_list_empty (& peer -> dispatchedCommands))
     return NULL;

   incomingCommand = (SecUdpIncomingCommand *) secudp_list_remove (secudp_list_begin (& peer -> dispatchedCommands));

   if (channelID != NULL)
     * channelID = incomingCommand -> command.header.channelID;

   packet = incomingCommand -> packet;

   -- packet -> referenceCount;

   if (incomingCommand -> fragments != NULL)
     secudp_free (incomingCommand -> fragments);

   secudp_free (incomingCommand);

   /*
    *  One man's ciphertext is another's data.
    *  data here is actually the ciphertext of the
    *  sender, so decrypt that into ciphertext and 
    *  do a swap.
    */
   if(packet -> dataLength < SECUDP_NONCEBYTES + SECUDP_MACBYTES)
   {
       secudp_packet_destroy(packet);
       return NULL;
   }
   ciphertext = packet -> data;
   cipherLength = packet -> dataLength;
   dataLength = cipherLength - SECUDP_NONCEBYTES - SECUDP_MACBYTES;
   data = secudp_malloc(dataLength);
   if(data == NULL)
   {
       secudp_packet_destroy(packet);
       return NULL;
   }
   nonce = ciphertext + dataLength;
   mac = nonce + SECUDP_NONCEBYTES;
   
   /*
    *  Decrypt the data and return NULL if it's bad data. 
    *  Special step not in ENet.
    */
   if(secudp_peer_decrypt(data, ciphertext, mac, dataLength, nonce, peer -> secret -> sessionPair.recvKey))
   {
     printf("Failed decryption\n");
       
     secudp_packet_destroy(packet);
     secudp_free(data);
     return NULL;
   } 
   
   packet -> ciphertext = ciphertext;
   packet -> data = data;
   packet -> dataLength = dataLength;
   packet -> cipherLength = cipherLength;
   
   peer -> totalWaitingData -= packet -> cipherLength;
   return packet;
}

static void
secudp_peer_reset_outgoing_commands (SecUdpList * queue)
{
    SecUdpOutgoingCommand * outgoingCommand;

    while (! secudp_list_empty (queue))
    {
       outgoingCommand = (SecUdpOutgoingCommand *) secudp_list_remove (secudp_list_begin (queue));

       if (outgoingCommand -> packet != NULL)
       {
          -- outgoingCommand -> packet -> referenceCount;

          if (outgoingCommand -> packet -> referenceCount == 0)
            secudp_packet_destroy (outgoingCommand -> packet);
       }

       secudp_free (outgoingCommand);
    }
}

static void
secudp_peer_remove_incoming_commands (SecUdpList * queue, SecUdpListIterator startCommand, SecUdpListIterator endCommand, SecUdpIncomingCommand * excludeCommand)
{
    SecUdpListIterator currentCommand;    
    
    for (currentCommand = startCommand; currentCommand != endCommand; )
    {
       SecUdpIncomingCommand * incomingCommand = (SecUdpIncomingCommand *) currentCommand;

       currentCommand = secudp_list_next (currentCommand);

       if (incomingCommand == excludeCommand)
         continue;

       secudp_list_remove (& incomingCommand -> incomingCommandList);
 
       if (incomingCommand -> packet != NULL)
       {
          -- incomingCommand -> packet -> referenceCount;

          if (incomingCommand -> packet -> referenceCount == 0)
            secudp_packet_destroy (incomingCommand -> packet);
       }

       if (incomingCommand -> fragments != NULL)
         secudp_free (incomingCommand -> fragments);

       secudp_free (incomingCommand);
    }
}

static void
secudp_peer_reset_incoming_commands (SecUdpList * queue)
{
    secudp_peer_remove_incoming_commands(queue, secudp_list_begin (queue), secudp_list_end (queue), NULL);
}
 
void
secudp_peer_reset_queues (SecUdpPeer * peer)
{
    SecUdpChannel * channel;

    if (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH)
    {
       secudp_list_remove (& peer -> dispatchList);

       peer -> flags &= ~ SECUDP_PEER_FLAG_NEEDS_DISPATCH;
    }

    while (! secudp_list_empty (& peer -> acknowledgements))
      secudp_free (secudp_list_remove (secudp_list_begin (& peer -> acknowledgements)));

    secudp_peer_reset_outgoing_commands (& peer -> sentReliableCommands);
    secudp_peer_reset_outgoing_commands (& peer -> sentUnreliableCommands);
    secudp_peer_reset_outgoing_commands (& peer -> outgoingCommands);
    secudp_peer_reset_incoming_commands (& peer -> dispatchedCommands);

    if (peer -> channels != NULL && peer -> channelCount > 0)
    {
        for (channel = peer -> channels;
             channel < & peer -> channels [peer -> channelCount];
             ++ channel)
        {
            secudp_peer_reset_incoming_commands (& channel -> incomingReliableCommands);
            secudp_peer_reset_incoming_commands (& channel -> incomingUnreliableCommands);
        }

        secudp_free (peer -> channels);
    }

    peer -> channels = NULL;
    peer -> channelCount = 0;
}

void
secudp_peer_on_connect (SecUdpPeer * peer)
{
    if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
    {
        if (peer -> incomingBandwidth != 0)
          ++ peer -> host -> bandwidthLimitedPeers;

        ++ peer -> host -> connectedPeers;
    }
}

void
secudp_peer_on_disconnect (SecUdpPeer * peer)
{
    if (peer -> state == SECUDP_PEER_STATE_CONNECTED || peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER)
    {
        if (peer -> incomingBandwidth != 0)
          -- peer -> host -> bandwidthLimitedPeers;

        -- peer -> host -> connectedPeers;
    }
}

/** Forcefully disconnects a peer.
    @param peer peer to forcefully disconnect
    @remarks The foreign host represented by the peer is not notified of the disconnection and will timeout
    on its connection to the local host.
*/
void
secudp_peer_reset (SecUdpPeer * peer)
{
    secudp_peer_on_disconnect (peer);
        
    peer -> outgoingPeerID = SECUDP_PROTOCOL_MAXIMUM_PEER_ID;
    peer -> connectID = 0;

    peer -> state = SECUDP_PEER_STATE_DISCONNECTED;

    peer -> incomingBandwidth = 0;
    peer -> outgoingBandwidth = 0;
    peer -> incomingBandwidthThrottleEpoch = 0;
    peer -> outgoingBandwidthThrottleEpoch = 0;
    peer -> incomingDataTotal = 0;
    peer -> outgoingDataTotal = 0;
    peer -> lastSendTime = 0;
    peer -> lastReceiveTime = 0;
    peer -> nextTimeout = 0;
    peer -> earliestTimeout = 0;
    peer -> packetLossEpoch = 0;
    peer -> packetsSent = 0;
    peer -> packetsLost = 0;
    peer -> packetLoss = 0;
    peer -> packetLossVariance = 0;
    peer -> packetThrottle = SECUDP_PEER_DEFAULT_PACKET_THROTTLE;
    peer -> packetThrottleLimit = SECUDP_PEER_PACKET_THROTTLE_SCALE;
    peer -> packetThrottleCounter = 0;
    peer -> packetThrottleEpoch = 0;
    peer -> packetThrottleAcceleration = SECUDP_PEER_PACKET_THROTTLE_ACCELERATION;
    peer -> packetThrottleDeceleration = SECUDP_PEER_PACKET_THROTTLE_DECELERATION;
    peer -> packetThrottleInterval = SECUDP_PEER_PACKET_THROTTLE_INTERVAL;
    peer -> pingInterval = SECUDP_PEER_PING_INTERVAL;
    peer -> timeoutLimit = SECUDP_PEER_TIMEOUT_LIMIT;
    peer -> timeoutMinimum = SECUDP_PEER_TIMEOUT_MINIMUM;
    peer -> timeoutMaximum = SECUDP_PEER_TIMEOUT_MAXIMUM;
    peer -> lastRoundTripTime = SECUDP_PEER_DEFAULT_ROUND_TRIP_TIME;
    peer -> lowestRoundTripTime = SECUDP_PEER_DEFAULT_ROUND_TRIP_TIME;
    peer -> lastRoundTripTimeVariance = 0;
    peer -> highestRoundTripTimeVariance = 0;
    peer -> roundTripTime = SECUDP_PEER_DEFAULT_ROUND_TRIP_TIME;
    peer -> roundTripTimeVariance = 0;
    peer -> mtu = peer -> host -> mtu;
    peer -> reliableDataInTransit = 0;
    peer -> outgoingReliableSequenceNumber = 0;
    peer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    peer -> incomingUnsequencedGroup = 0;
    peer -> outgoingUnsequencedGroup = 0;
    peer -> eventData = 0;
    peer -> totalWaitingData = 0;
    peer -> flags = 0;

    memset (peer -> unsequencedWindow, 0, sizeof (peer -> unsequencedWindow));
    
    secudp_peer_reset_queues (peer);
}

/** Sends a ping request to a peer.
    @param peer destination for the ping request
    @remarks ping requests factor into the mean round trip time as designated by the 
    roundTripTime field in the SecUdpPeer structure.  SecUdp automatically pings all connected
    peers at regular intervals, however, this function may be called to ensure more
    frequent ping requests.
*/
void
secudp_peer_ping (SecUdpPeer * peer)
{
    SecUdpProtocol command;

    if (peer -> state != SECUDP_PEER_STATE_CONNECTED)
      return;

    command.header.command = SECUDP_PROTOCOL_COMMAND_PING | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    command.header.channelID = 0xFF;
   
    secudp_peer_queue_outgoing_command (peer, & command, NULL, 0, 0);
}

/** Sets the interval at which pings will be sent to a peer. 
    
    Pings are used both to monitor the liveness of the connection and also to dynamically
    adjust the throttle during periods of low traffic so that the throttle has reasonable
    responsiveness during traffic spikes.

    @param peer the peer to adjust
    @param pingInterval the interval at which to send pings; defaults to SECUDP_PEER_PING_INTERVAL if 0
*/
void
secudp_peer_ping_interval (SecUdpPeer * peer, secudp_uint32 pingInterval)
{
    peer -> pingInterval = pingInterval ? pingInterval : SECUDP_PEER_PING_INTERVAL;
}

/** Sets the timeout parameters for a peer.

    The timeout parameter control how and when a peer will timeout from a failure to acknowledge
    reliable traffic. Timeout values use an exponential backoff mechanism, where if a reliable
    packet is not acknowledge within some multiple of the average RTT plus a variance tolerance, 
    the timeout will be doubled until it reaches a set limit. If the timeout is thus at this
    limit and reliable packets have been sent but not acknowledged within a certain minimum time 
    period, the peer will be disconnected. Alternatively, if reliable packets have been sent
    but not acknowledged for a certain maximum time period, the peer will be disconnected regardless
    of the current timeout limit value.
    
    @param peer the peer to adjust
    @param timeoutLimit the timeout limit; defaults to SECUDP_PEER_TIMEOUT_LIMIT if 0
    @param timeoutMinimum the timeout minimum; defaults to SECUDP_PEER_TIMEOUT_MINIMUM if 0
    @param timeoutMaximum the timeout maximum; defaults to SECUDP_PEER_TIMEOUT_MAXIMUM if 0
*/

void
secudp_peer_timeout (SecUdpPeer * peer, secudp_uint32 timeoutLimit, secudp_uint32 timeoutMinimum, secudp_uint32 timeoutMaximum)
{
    peer -> timeoutLimit = timeoutLimit ? timeoutLimit : SECUDP_PEER_TIMEOUT_LIMIT;
    peer -> timeoutMinimum = timeoutMinimum ? timeoutMinimum : SECUDP_PEER_TIMEOUT_MINIMUM;
    peer -> timeoutMaximum = timeoutMaximum ? timeoutMaximum : SECUDP_PEER_TIMEOUT_MAXIMUM;
}

/** Force an immediate disconnection from a peer.
    @param peer peer to disconnect
    @param data data describing the disconnection
    @remarks No SECUDP_EVENT_DISCONNECT event will be generated. The foreign peer is not
    guaranteed to receive the disconnect notification, and is reset immediately upon
    return from this function.
*/
void
secudp_peer_disconnect_now (SecUdpPeer * peer, secudp_uint32 data)
{
    SecUdpProtocol command;

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECTED)
      return;

    if (peer -> state != SECUDP_PEER_STATE_ZOMBIE &&
        peer -> state != SECUDP_PEER_STATE_DISCONNECTING)
    {
        secudp_peer_reset_queues (peer);

        command.header.command = SECUDP_PROTOCOL_COMMAND_DISCONNECT | SECUDP_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;
        command.header.channelID = 0xFF;
        command.disconnect.data = SECUDP_HOST_TO_NET_32 (data);

        secudp_peer_queue_outgoing_command (peer, & command, NULL, 0, 0);

        secudp_host_flush (peer -> host);
    }

    secudp_peer_reset (peer);
}

/** Request a disconnection from a peer.
    @param peer peer to request a disconnection
    @param data data describing the disconnection
    @remarks An SECUDP_EVENT_DISCONNECT event will be generated by secudp_host_service()
    once the disconnection is complete.
*/
void
secudp_peer_disconnect (SecUdpPeer * peer, secudp_uint32 data)
{
    SecUdpProtocol command;

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECTING ||
        peer -> state == SECUDP_PEER_STATE_DISCONNECTED ||
        peer -> state == SECUDP_PEER_STATE_ACKNOWLEDGING_DISCONNECT ||
        peer -> state == SECUDP_PEER_STATE_ZOMBIE)
      return;

    secudp_peer_reset_queues (peer);

    command.header.command = SECUDP_PROTOCOL_COMMAND_DISCONNECT;
    command.header.channelID = 0xFF;
    command.disconnect.data = SECUDP_HOST_TO_NET_32 (data);

    if (peer -> state == SECUDP_PEER_STATE_CONNECTED || peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER)
      command.header.command |= SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    else
      command.header.command |= SECUDP_PROTOCOL_COMMAND_FLAG_UNSEQUENCED;      
    
    secudp_peer_queue_outgoing_command (peer, & command, NULL, 0, 0);

    if (peer -> state == SECUDP_PEER_STATE_CONNECTED || peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER)
    {
        secudp_peer_on_disconnect (peer);

        peer -> state = SECUDP_PEER_STATE_DISCONNECTING;
    }
    else
    {
        secudp_host_flush (peer -> host);
        secudp_peer_reset (peer);
    }
}

/** Request a disconnection from a peer, but only after all queued outgoing packets are sent.
    @param peer peer to request a disconnection
    @param data data describing the disconnection
    @remarks An SECUDP_EVENT_DISCONNECT event will be generated by secudp_host_service()
    once the disconnection is complete.
*/
void
secudp_peer_disconnect_later (SecUdpPeer * peer, secudp_uint32 data)
{   
    if ((peer -> state == SECUDP_PEER_STATE_CONNECTED || peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER) && 
        ! (secudp_list_empty (& peer -> outgoingCommands) &&
           secudp_list_empty (& peer -> sentReliableCommands)))
    {
        peer -> state = SECUDP_PEER_STATE_DISCONNECT_LATER;
        peer -> eventData = data;
    }
    else
      secudp_peer_disconnect (peer, data);
}

SecUdpAcknowledgement *
secudp_peer_queue_acknowledgement (SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint16 sentTime)
{
    SecUdpAcknowledgement * acknowledgement;

    if (command -> header.channelID < peer -> channelCount)
    {
        SecUdpChannel * channel = & peer -> channels [command -> header.channelID];
        secudp_uint16 reliableWindow = command -> header.reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE,
                    currentWindow = channel -> incomingReliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;

        if (command -> header.reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
           reliableWindow += SECUDP_PEER_RELIABLE_WINDOWS;

        if (reliableWindow >= currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS - 1 && reliableWindow <= currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS)
          return NULL;
    }

    acknowledgement = (SecUdpAcknowledgement *) secudp_malloc (sizeof (SecUdpAcknowledgement));
    if (acknowledgement == NULL)
      return NULL;

    peer -> outgoingDataTotal += sizeof (SecUdpProtocolAcknowledge);

    acknowledgement -> sentTime = sentTime;
    acknowledgement -> command = * command;
    
    secudp_list_insert (secudp_list_end (& peer -> acknowledgements), acknowledgement);
    
    return acknowledgement;
}

void
secudp_peer_setup_outgoing_command (SecUdpPeer * peer, SecUdpOutgoingCommand * outgoingCommand)
{
    SecUdpChannel * channel = & peer -> channels [outgoingCommand -> command.header.channelID];
    
    peer -> outgoingDataTotal += secudp_protocol_command_size (outgoingCommand -> command.header.command) + outgoingCommand -> fragmentLength;

    if (outgoingCommand -> command.header.channelID == 0xFF)
    {
       ++ peer -> outgoingReliableSequenceNumber;

       outgoingCommand -> reliableSequenceNumber = peer -> outgoingReliableSequenceNumber;
       outgoingCommand -> unreliableSequenceNumber = 0;
    }
    else
    if (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
    {
       ++ channel -> outgoingReliableSequenceNumber;
       channel -> outgoingUnreliableSequenceNumber = 0;

       outgoingCommand -> reliableSequenceNumber = channel -> outgoingReliableSequenceNumber;
       outgoingCommand -> unreliableSequenceNumber = 0;
    }
    else
    if (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_UNSEQUENCED)
    {
       ++ peer -> outgoingUnsequencedGroup;

       outgoingCommand -> reliableSequenceNumber = 0;
       outgoingCommand -> unreliableSequenceNumber = 0;
    }
    else
    {
       if (outgoingCommand -> fragmentOffset == 0)
         ++ channel -> outgoingUnreliableSequenceNumber;
        
       outgoingCommand -> reliableSequenceNumber = channel -> outgoingReliableSequenceNumber;
       outgoingCommand -> unreliableSequenceNumber = channel -> outgoingUnreliableSequenceNumber;
    }
   
    outgoingCommand -> sendAttempts = 0;
    outgoingCommand -> sentTime = 0;
    outgoingCommand -> roundTripTimeout = 0;
    outgoingCommand -> roundTripTimeoutLimit = 0;
    outgoingCommand -> command.header.reliableSequenceNumber = SECUDP_HOST_TO_NET_16 (outgoingCommand -> reliableSequenceNumber);

    switch (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK)
    {
    case SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE:
        outgoingCommand -> command.sendUnreliable.unreliableSequenceNumber = SECUDP_HOST_TO_NET_16 (outgoingCommand -> unreliableSequenceNumber);
        break;

    case SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
        outgoingCommand -> command.sendUnsequenced.unsequencedGroup = SECUDP_HOST_TO_NET_16 (peer -> outgoingUnsequencedGroup);
        break;
    
    default:
        break;
    }

    secudp_list_insert (secudp_list_end (& peer -> outgoingCommands), outgoingCommand);
}

SecUdpOutgoingCommand *
secudp_peer_queue_outgoing_command (SecUdpPeer * peer, const SecUdpProtocol * command, SecUdpPacket * packet, secudp_uint32 offset, secudp_uint16 length)
{
    SecUdpOutgoingCommand * outgoingCommand = (SecUdpOutgoingCommand *) secudp_malloc (sizeof (SecUdpOutgoingCommand));
    if (outgoingCommand == NULL)
      return NULL;

    outgoingCommand -> command = * command;
    outgoingCommand -> fragmentOffset = offset;
    outgoingCommand -> fragmentLength = length;
    outgoingCommand -> packet = packet;
    if (packet != NULL)
      ++ packet -> referenceCount;

    secudp_peer_setup_outgoing_command (peer, outgoingCommand);

    return outgoingCommand;
}

void
secudp_peer_dispatch_incoming_unreliable_commands (SecUdpPeer * peer, SecUdpChannel * channel, SecUdpIncomingCommand * queuedCommand)
{
    SecUdpListIterator droppedCommand, startCommand, currentCommand;

    for (droppedCommand = startCommand = currentCommand = secudp_list_begin (& channel -> incomingUnreliableCommands);
         currentCommand != secudp_list_end (& channel -> incomingUnreliableCommands);
         currentCommand = secudp_list_next (currentCommand))
    {
       SecUdpIncomingCommand * incomingCommand = (SecUdpIncomingCommand *) currentCommand;

       if ((incomingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK) == SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED)
         continue;

       if (incomingCommand -> reliableSequenceNumber == channel -> incomingReliableSequenceNumber)
       {
          if (incomingCommand -> fragmentsRemaining <= 0)
          {
             channel -> incomingUnreliableSequenceNumber = incomingCommand -> unreliableSequenceNumber;
             continue;
          }

          if (startCommand != currentCommand)
          {
             secudp_list_move (secudp_list_end (& peer -> dispatchedCommands), startCommand, secudp_list_previous (currentCommand));

             if (! (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH))
             {
                secudp_list_insert (secudp_list_end (& peer -> host -> dispatchQueue), & peer -> dispatchList);

                peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
             }

             droppedCommand = currentCommand;
          }
          else
          if (droppedCommand != currentCommand)
            droppedCommand = secudp_list_previous (currentCommand);
       }
       else 
       {
          secudp_uint16 reliableWindow = incomingCommand -> reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE,
                      currentWindow = channel -> incomingReliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
          if (incomingCommand -> reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
            reliableWindow += SECUDP_PEER_RELIABLE_WINDOWS;
          if (reliableWindow >= currentWindow && reliableWindow < currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS - 1)
            break;

          droppedCommand = secudp_list_next (currentCommand);

          if (startCommand != currentCommand)
          {
             secudp_list_move (secudp_list_end (& peer -> dispatchedCommands), startCommand, secudp_list_previous (currentCommand));

             if (! (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH))
             {
                secudp_list_insert (secudp_list_end (& peer -> host -> dispatchQueue), & peer -> dispatchList);

                peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
             }
          }
       }
          
       startCommand = secudp_list_next (currentCommand);
    }

    if (startCommand != currentCommand)
    {
       secudp_list_move (secudp_list_end (& peer -> dispatchedCommands), startCommand, secudp_list_previous (currentCommand));

       if (! (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH))
       {
           secudp_list_insert (secudp_list_end (& peer -> host -> dispatchQueue), & peer -> dispatchList);

           peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
       }

       droppedCommand = currentCommand;
    }

    secudp_peer_remove_incoming_commands (& channel -> incomingUnreliableCommands, secudp_list_begin (& channel -> incomingUnreliableCommands), droppedCommand, queuedCommand);
}

void
secudp_peer_dispatch_incoming_reliable_commands (SecUdpPeer * peer, SecUdpChannel * channel, SecUdpIncomingCommand * queuedCommand)
{
    SecUdpListIterator currentCommand;

    for (currentCommand = secudp_list_begin (& channel -> incomingReliableCommands);
         currentCommand != secudp_list_end (& channel -> incomingReliableCommands);
         currentCommand = secudp_list_next (currentCommand))
    {
       SecUdpIncomingCommand * incomingCommand = (SecUdpIncomingCommand *) currentCommand;
         
       if (incomingCommand -> fragmentsRemaining > 0 ||
           incomingCommand -> reliableSequenceNumber != (secudp_uint16) (channel -> incomingReliableSequenceNumber + 1))
         break;

       channel -> incomingReliableSequenceNumber = incomingCommand -> reliableSequenceNumber;

       if (incomingCommand -> fragmentCount > 0)
         channel -> incomingReliableSequenceNumber += incomingCommand -> fragmentCount - 1;
    } 

    if (currentCommand == secudp_list_begin (& channel -> incomingReliableCommands))
      return;

    channel -> incomingUnreliableSequenceNumber = 0;

    secudp_list_move (secudp_list_end (& peer -> dispatchedCommands), secudp_list_begin (& channel -> incomingReliableCommands), secudp_list_previous (currentCommand));

    if (! (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH))
    {
       secudp_list_insert (secudp_list_end (& peer -> host -> dispatchQueue), & peer -> dispatchList);

       peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
    }

    if (! secudp_list_empty (& channel -> incomingUnreliableCommands))
       secudp_peer_dispatch_incoming_unreliable_commands (peer, channel, queuedCommand);
}

SecUdpIncomingCommand *
secudp_peer_queue_incoming_command (SecUdpPeer * peer, const SecUdpProtocol * command, const void * data, size_t dataLength, secudp_uint32 flags, secudp_uint32 fragmentCount)
{
    static SecUdpIncomingCommand dummyCommand;

    SecUdpChannel * channel = & peer -> channels [command -> header.channelID];
    secudp_uint32 unreliableSequenceNumber = 0, reliableSequenceNumber = 0;
    secudp_uint16 reliableWindow, currentWindow;
    SecUdpIncomingCommand * incomingCommand;
    SecUdpListIterator currentCommand;
    SecUdpPacket * packet = NULL;

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER)
      goto discardCommand;

    if ((command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK) != SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED)
    {
        reliableSequenceNumber = command -> header.reliableSequenceNumber;
        reliableWindow = reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
        currentWindow = channel -> incomingReliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;

        if (reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
           reliableWindow += SECUDP_PEER_RELIABLE_WINDOWS;

        if (reliableWindow < currentWindow || reliableWindow >= currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS - 1)
          goto discardCommand;
    }
                    
    switch (command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK)
    {
    case SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT:
    case SECUDP_PROTOCOL_COMMAND_SEND_RELIABLE:
       if (reliableSequenceNumber == channel -> incomingReliableSequenceNumber)
         goto discardCommand;
       
       for (currentCommand = secudp_list_previous (secudp_list_end (& channel -> incomingReliableCommands));
            currentCommand != secudp_list_end (& channel -> incomingReliableCommands);
            currentCommand = secudp_list_previous (currentCommand))
       {
          incomingCommand = (SecUdpIncomingCommand *) currentCommand;

          if (reliableSequenceNumber >= channel -> incomingReliableSequenceNumber)
          {
             if (incomingCommand -> reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
               continue;
          }
          else
          if (incomingCommand -> reliableSequenceNumber >= channel -> incomingReliableSequenceNumber)
            break;

          if (incomingCommand -> reliableSequenceNumber <= reliableSequenceNumber)
          {
             if (incomingCommand -> reliableSequenceNumber < reliableSequenceNumber)
               break;

             goto discardCommand;
          }
       }
       break;

    case SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE:
    case SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
       unreliableSequenceNumber = SECUDP_NET_TO_HOST_16 (command -> sendUnreliable.unreliableSequenceNumber);

       if (reliableSequenceNumber == channel -> incomingReliableSequenceNumber && 
           unreliableSequenceNumber <= channel -> incomingUnreliableSequenceNumber)
         goto discardCommand;

       for (currentCommand = secudp_list_previous (secudp_list_end (& channel -> incomingUnreliableCommands));
            currentCommand != secudp_list_end (& channel -> incomingUnreliableCommands);
            currentCommand = secudp_list_previous (currentCommand))
       {
          incomingCommand = (SecUdpIncomingCommand *) currentCommand;

          if ((command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK) == SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED)
            continue;

          if (reliableSequenceNumber >= channel -> incomingReliableSequenceNumber)
          {
             if (incomingCommand -> reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
               continue;
          }
          else
          if (incomingCommand -> reliableSequenceNumber >= channel -> incomingReliableSequenceNumber)
            break;

          if (incomingCommand -> reliableSequenceNumber < reliableSequenceNumber)
            break;

          if (incomingCommand -> reliableSequenceNumber > reliableSequenceNumber)
            continue;

          if (incomingCommand -> unreliableSequenceNumber <= unreliableSequenceNumber)
          {
             if (incomingCommand -> unreliableSequenceNumber < unreliableSequenceNumber)
               break;

             goto discardCommand;
          }
       }
       break;

    case SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
       currentCommand = secudp_list_end (& channel -> incomingUnreliableCommands);
       break;

    default:
       goto discardCommand;
    }

    if (peer -> totalWaitingData >= peer -> host -> maximumWaitingData)
      goto notifyError;

    packet = secudp_packet_create (data, dataLength, flags);
    if (packet == NULL)
      goto notifyError;

    incomingCommand = (SecUdpIncomingCommand *) secudp_malloc (sizeof (SecUdpIncomingCommand));
    if (incomingCommand == NULL)
      goto notifyError;

    incomingCommand -> reliableSequenceNumber = command -> header.reliableSequenceNumber;
    incomingCommand -> unreliableSequenceNumber = unreliableSequenceNumber & 0xFFFF;
    incomingCommand -> command = * command;
    incomingCommand -> fragmentCount = fragmentCount;
    incomingCommand -> fragmentsRemaining = fragmentCount;
    incomingCommand -> packet = packet;
    incomingCommand -> fragments = NULL;
    
    if (fragmentCount > 0)
    { 
       if (fragmentCount <= SECUDP_PROTOCOL_MAXIMUM_FRAGMENT_COUNT)
         incomingCommand -> fragments = (secudp_uint32 *) secudp_malloc ((fragmentCount + 31) / 32 * sizeof (secudp_uint32));
       if (incomingCommand -> fragments == NULL)
       {
          secudp_free (incomingCommand);

          goto notifyError;
       }
       memset (incomingCommand -> fragments, 0, (fragmentCount + 31) / 32 * sizeof (secudp_uint32));
    }

    if (packet != NULL)
    {
       ++ packet -> referenceCount;
      
       peer -> totalWaitingData += packet -> cipherLength;
    }

    secudp_list_insert (secudp_list_next (currentCommand), incomingCommand);

    switch (command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK)
    {
    case SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT:
    case SECUDP_PROTOCOL_COMMAND_SEND_RELIABLE:
       secudp_peer_dispatch_incoming_reliable_commands (peer, channel, incomingCommand);
       break;

    default:
       secudp_peer_dispatch_incoming_unreliable_commands (peer, channel, incomingCommand);
       break;
    }

    return incomingCommand;

discardCommand:
    if (fragmentCount > 0)
      goto notifyError;

    if (packet != NULL && packet -> referenceCount == 0)
      secudp_packet_destroy (packet);

    return & dummyCommand;

notifyError:
    if (packet != NULL && packet -> referenceCount == 0)
      secudp_packet_destroy (packet);

    return NULL;
}

/** @} */
