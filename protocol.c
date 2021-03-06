/** 
 @file  protocol.c
 @brief SecUdp protocol functions
*/
#include <stdio.h>
#include <string.h>
#define SECUDP_BUILDING_LIB 1
#include "secudp/utility.h"
#include "secudp/time.h"
#include "secudp/secudp.h"

static size_t commandSizes [SECUDP_PROTOCOL_COMMAND_COUNT] =
{
    0,
    sizeof (SecUdpProtocolAcknowledge),
    sizeof (SecUdpProtocolConnect),
    sizeof (SecUdpProtocolVerifyConnect),
    sizeof (SecUdpProtocolDisconnect),
    sizeof (SecUdpProtocolPing),
    sizeof (SecUdpProtocolSendReliable),
    sizeof (SecUdpProtocolSendUnreliable),
    sizeof (SecUdpProtocolSendFragment),
    sizeof (SecUdpProtocolSendUnsequenced),
    sizeof (SecUdpProtocolBandwidthLimit),
    sizeof (SecUdpProtocolThrottleConfigure),
    sizeof (SecUdpProtocolSendFragment)
};

size_t
secudp_protocol_command_size (secudp_uint8 commandNumber)
{
    return commandSizes [commandNumber & SECUDP_PROTOCOL_COMMAND_MASK];
}

static void
secudp_protocol_change_state (SecUdpHost * host, SecUdpPeer * peer, SecUdpPeerState state)
{
    if (state == SECUDP_PEER_STATE_CONNECTED || state == SECUDP_PEER_STATE_DISCONNECT_LATER)
      secudp_peer_on_connect (peer);
    else
      secudp_peer_on_disconnect (peer);

    peer -> state = state;
}

static void
secudp_protocol_dispatch_state (SecUdpHost * host, SecUdpPeer * peer, SecUdpPeerState state)
{
    secudp_protocol_change_state (host, peer, state);

    if (! (peer -> flags & SECUDP_PEER_FLAG_NEEDS_DISPATCH))
    {
       secudp_list_insert (secudp_list_end (& host -> dispatchQueue), & peer -> dispatchList);

       peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
    }
}

static int
secudp_protocol_dispatch_incoming_commands (SecUdpHost * host, SecUdpEvent * event)
{
    while (! secudp_list_empty (& host -> dispatchQueue))
    {
       SecUdpPeer * peer = (SecUdpPeer *) secudp_list_remove (secudp_list_begin (& host -> dispatchQueue));

       peer -> flags &= ~ SECUDP_PEER_FLAG_NEEDS_DISPATCH;

       switch (peer -> state)
       {
       case SECUDP_PEER_STATE_CONNECTION_PENDING:
       case SECUDP_PEER_STATE_CONNECTION_SUCCEEDED:
           secudp_protocol_change_state (host, peer, SECUDP_PEER_STATE_CONNECTED);

           /* 
            *  TODO: Hold off on sending the connect event until after the peer
            *        and host do the handshake.
            */
           event -> type = SECUDP_EVENT_TYPE_CONNECT;
           event -> peer = peer;
           event -> data = peer -> eventData;

           return 1;
           
       case SECUDP_PEER_STATE_ZOMBIE:
           host -> recalculateBandwidthLimits = 1;

           event -> type = SECUDP_EVENT_TYPE_DISCONNECT;
           event -> peer = peer;
           event -> data = peer -> eventData;

           secudp_peer_reset (peer);

           return 1;

       case SECUDP_PEER_STATE_CONNECTED:
           if (secudp_list_empty (& peer -> dispatchedCommands))
             continue;

           event -> packet = secudp_peer_receive (peer, & event -> channelID);
           if (event -> packet == NULL)
             continue;
             
           event -> type = SECUDP_EVENT_TYPE_RECEIVE;
           event -> peer = peer;

           if (! secudp_list_empty (& peer -> dispatchedCommands))
           {
              peer -> flags |= SECUDP_PEER_FLAG_NEEDS_DISPATCH;
         
              secudp_list_insert (secudp_list_end (& host -> dispatchQueue), & peer -> dispatchList);
           }

           return 1;

       default:
           break;
       }
    }

    return 0;
}

static void
secudp_protocol_notify_connect (SecUdpHost * host, SecUdpPeer * peer, SecUdpEvent * event)
{
    host -> recalculateBandwidthLimits = 1;

    if (event != NULL)
    {
        secudp_protocol_change_state (host, peer, SECUDP_PEER_STATE_CONNECTED);

        /* 
         *  TODO: Hold off on sending the connect event until after the peer
         *        and host do the handshake.
         */
        event -> type = SECUDP_EVENT_TYPE_CONNECT;
        event -> peer = peer;
        event -> data = peer -> eventData;
    }
    else 
        secudp_protocol_dispatch_state (host, peer, peer -> state == SECUDP_PEER_STATE_CONNECTING ? SECUDP_PEER_STATE_CONNECTION_SUCCEEDED : SECUDP_PEER_STATE_CONNECTION_PENDING);
}

static void
secudp_protocol_notify_disconnect (SecUdpHost * host, SecUdpPeer * peer, SecUdpEvent * event)
{
    if (peer -> state >= SECUDP_PEER_STATE_CONNECTION_PENDING)
       host -> recalculateBandwidthLimits = 1;

    if (peer -> state != SECUDP_PEER_STATE_CONNECTING && peer -> state < SECUDP_PEER_STATE_CONNECTION_SUCCEEDED)
        secudp_peer_reset (peer);
    else
    if (event != NULL)
    {
        event -> type = SECUDP_EVENT_TYPE_DISCONNECT;
        event -> peer = peer;
        event -> data = 0;

        secudp_peer_reset (peer);
    }
    else 
    {
        peer -> eventData = 0;

        secudp_protocol_dispatch_state (host, peer, SECUDP_PEER_STATE_ZOMBIE);
    }
}

static void
secudp_protocol_remove_sent_unreliable_commands (SecUdpPeer * peer)
{
    SecUdpOutgoingCommand * outgoingCommand;

    if (secudp_list_empty (& peer -> sentUnreliableCommands))
      return;

    do
    {
        outgoingCommand = (SecUdpOutgoingCommand *) secudp_list_front (& peer -> sentUnreliableCommands);
        
        secudp_list_remove (& outgoingCommand -> outgoingCommandList);

        if (outgoingCommand -> packet != NULL)
        {
           -- outgoingCommand -> packet -> referenceCount;

           if (outgoingCommand -> packet -> referenceCount == 0)
           {
              outgoingCommand -> packet -> flags |= SECUDP_PACKET_FLAG_SENT;
 
              secudp_packet_destroy (outgoingCommand -> packet);
           }
        }

        secudp_free (outgoingCommand);
    } while (! secudp_list_empty (& peer -> sentUnreliableCommands));

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER &&
        secudp_list_empty (& peer -> outgoingCommands) &&
        secudp_list_empty (& peer -> sentReliableCommands))
      secudp_peer_disconnect (peer, peer -> eventData);
}

static SecUdpProtocolCommand
secudp_protocol_remove_sent_reliable_command (SecUdpPeer * peer, secudp_uint16 reliableSequenceNumber, secudp_uint8 channelID)
{
    SecUdpOutgoingCommand * outgoingCommand = NULL;
    SecUdpListIterator currentCommand;
    SecUdpProtocolCommand commandNumber;
    int wasSent = 1;

    for (currentCommand = secudp_list_begin (& peer -> sentReliableCommands);
         currentCommand != secudp_list_end (& peer -> sentReliableCommands);
         currentCommand = secudp_list_next (currentCommand))
    {
       outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;
        
       if (outgoingCommand -> reliableSequenceNumber == reliableSequenceNumber &&
           outgoingCommand -> command.header.channelID == channelID)
         break;
    }

    if (currentCommand == secudp_list_end (& peer -> sentReliableCommands))
    {
       for (currentCommand = secudp_list_begin (& peer -> outgoingCommands);
            currentCommand != secudp_list_end (& peer -> outgoingCommands);
            currentCommand = secudp_list_next (currentCommand))
       {
          outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;

          if (! (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE))
            continue;

          if (outgoingCommand -> sendAttempts < 1) return SECUDP_PROTOCOL_COMMAND_NONE;

          if (outgoingCommand -> reliableSequenceNumber == reliableSequenceNumber &&
              outgoingCommand -> command.header.channelID == channelID)
            break;
       }

       if (currentCommand == secudp_list_end (& peer -> outgoingCommands))
         return SECUDP_PROTOCOL_COMMAND_NONE;

       wasSent = 0;
    }

    if (outgoingCommand == NULL)
      return SECUDP_PROTOCOL_COMMAND_NONE;

    if (channelID < peer -> channelCount)
    {
       SecUdpChannel * channel = & peer -> channels [channelID];
       secudp_uint16 reliableWindow = reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
       if (channel -> reliableWindows [reliableWindow] > 0)
       {
          -- channel -> reliableWindows [reliableWindow];
          if (! channel -> reliableWindows [reliableWindow])
            channel -> usedReliableWindows &= ~ (1 << reliableWindow);
       }
    }

    commandNumber = (SecUdpProtocolCommand) (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK);
    
    secudp_list_remove (& outgoingCommand -> outgoingCommandList);

    if (outgoingCommand -> packet != NULL)
    {
       if (wasSent)
         peer -> reliableDataInTransit -= outgoingCommand -> fragmentLength;

       -- outgoingCommand -> packet -> referenceCount;

       if (outgoingCommand -> packet -> referenceCount == 0)
       {
          outgoingCommand -> packet -> flags |= SECUDP_PACKET_FLAG_SENT;

          secudp_packet_destroy (outgoingCommand -> packet);
       }
    }

    secudp_free (outgoingCommand);

    if (secudp_list_empty (& peer -> sentReliableCommands))
      return commandNumber;
    
    outgoingCommand = (SecUdpOutgoingCommand *) secudp_list_front (& peer -> sentReliableCommands);
    
    peer -> nextTimeout = outgoingCommand -> sentTime + outgoingCommand -> roundTripTimeout;

    return commandNumber;
} 

static SecUdpPeer *
secudp_protocol_handle_connect (SecUdpHost * host, SecUdpProtocolHeader * header, SecUdpProtocol * command)
{
    secudp_uint8 incomingSessionID, outgoingSessionID;
    secudp_uint32 mtu, windowSize;
    SecUdpChannel * channel;
    size_t channelCount, duplicatePeers = 0;
    SecUdpPeer * currentPeer, * peer = NULL;
    SecUdpProtocol verifyCommand;
    SecUdpPeerSecret secret;

    channelCount = SECUDP_NET_TO_HOST_32 (command -> connect.channelCount);

    if (channelCount < SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT ||
        channelCount > SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT)
      return NULL;

    for (currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
        if (currentPeer -> state == SECUDP_PEER_STATE_DISCONNECTED)
        {
            if (peer == NULL)
              peer = currentPeer;
        }
        else 
        if (currentPeer -> state != SECUDP_PEER_STATE_CONNECTING &&
            currentPeer -> address.host == host -> receivedAddress.host)
        {
            if (currentPeer -> address.port == host -> receivedAddress.port &&
                currentPeer -> connectID == command -> connect.connectID)
              return NULL;

            ++ duplicatePeers;
        }
    }

    if (peer == NULL || duplicatePeers >= host -> duplicatePeers)
      return NULL;

    if (channelCount > host -> channelLimit)
      channelCount = host -> channelLimit;
    peer -> channels = (SecUdpChannel *) secudp_malloc (channelCount * sizeof (SecUdpChannel));
    if (peer -> channels == NULL)
      return NULL;
      
    /*
     *  Additionally generate a secret key pair for use
     *  in key exchange. Extension of ENet.
     */
    peer -> secret = (SecUdpPeerSecret *) secudp_malloc (sizeof(SecUdpPeerSecret));
    if (peer -> secret == NULL)
    {
        secudp_free(peer -> channels);
        return NULL;
    }
    secudp_peer_gen_key_exchange_pair(peer -> secret -> kxPair.publicKx, peer -> secret -> kxPair.privateKx);
    if(secudp_host_gen_session_keys(secret.sessionPair.sendKey, secret.sessionPair.recvKey, peer -> secret -> kxPair.publicKx, peer -> secret -> kxPair.privateKx, command -> connect.publicKx))
    {
        secudp_free(peer -> channels);
        secudp_free(peer -> secret);
        return NULL;
    }
    
    peer -> channelCount = channelCount;
    peer -> state = SECUDP_PEER_STATE_ACKNOWLEDGING_CONNECT;
    peer -> connectID = command -> connect.connectID;
    peer -> address = host -> receivedAddress;
    peer -> outgoingPeerID = SECUDP_NET_TO_HOST_16 (command -> connect.outgoingPeerID);
    peer -> incomingBandwidth = SECUDP_NET_TO_HOST_32 (command -> connect.incomingBandwidth);
    peer -> outgoingBandwidth = SECUDP_NET_TO_HOST_32 (command -> connect.outgoingBandwidth);
    peer -> packetThrottleInterval = SECUDP_NET_TO_HOST_32 (command -> connect.packetThrottleInterval);
    peer -> packetThrottleAcceleration = SECUDP_NET_TO_HOST_32 (command -> connect.packetThrottleAcceleration);
    peer -> packetThrottleDeceleration = SECUDP_NET_TO_HOST_32 (command -> connect.packetThrottleDeceleration);
    peer -> eventData = SECUDP_NET_TO_HOST_32 (command -> connect.data);

    incomingSessionID = command -> connect.incomingSessionID == 0xFF ? peer -> outgoingSessionID : command -> connect.incomingSessionID;
    incomingSessionID = (incomingSessionID + 1) & (SECUDP_PROTOCOL_HEADER_SESSION_MASK >> SECUDP_PROTOCOL_HEADER_SESSION_SHIFT);
    if (incomingSessionID == peer -> outgoingSessionID)
      incomingSessionID = (incomingSessionID + 1) & (SECUDP_PROTOCOL_HEADER_SESSION_MASK >> SECUDP_PROTOCOL_HEADER_SESSION_SHIFT);
    peer -> outgoingSessionID = incomingSessionID;

    outgoingSessionID = command -> connect.outgoingSessionID == 0xFF ? peer -> incomingSessionID : command -> connect.outgoingSessionID;
    outgoingSessionID = (outgoingSessionID + 1) & (SECUDP_PROTOCOL_HEADER_SESSION_MASK >> SECUDP_PROTOCOL_HEADER_SESSION_SHIFT);
    if (outgoingSessionID == peer -> incomingSessionID)
      outgoingSessionID = (outgoingSessionID + 1) & (SECUDP_PROTOCOL_HEADER_SESSION_MASK >> SECUDP_PROTOCOL_HEADER_SESSION_SHIFT);
    peer -> incomingSessionID = outgoingSessionID;

    for (channel = peer -> channels;
         channel < & peer -> channels [channelCount];
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

    mtu = SECUDP_NET_TO_HOST_32 (command -> connect.mtu);

    if (mtu < SECUDP_PROTOCOL_MINIMUM_MTU)
      mtu = SECUDP_PROTOCOL_MINIMUM_MTU;
    else
    if (mtu > SECUDP_PROTOCOL_MAXIMUM_MTU)
      mtu = SECUDP_PROTOCOL_MAXIMUM_MTU;

    peer -> mtu = mtu;

    if (host -> outgoingBandwidth == 0 &&
        peer -> incomingBandwidth == 0)
      peer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
    if (host -> outgoingBandwidth == 0 ||
        peer -> incomingBandwidth == 0)
      peer -> windowSize = (SECUDP_MAX (host -> outgoingBandwidth, peer -> incomingBandwidth) /
                                    SECUDP_PEER_WINDOW_SIZE_SCALE) *
                                      SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
      peer -> windowSize = (SECUDP_MIN (host -> outgoingBandwidth, peer -> incomingBandwidth) /
                                    SECUDP_PEER_WINDOW_SIZE_SCALE) * 
                                      SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (peer -> windowSize < SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE)
      peer -> windowSize = SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
    if (peer -> windowSize > SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE)
      peer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    if (host -> incomingBandwidth == 0)
      windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
      windowSize = (host -> incomingBandwidth / SECUDP_PEER_WINDOW_SIZE_SCALE) *
                     SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (windowSize > SECUDP_NET_TO_HOST_32 (command -> connect.windowSize))
      windowSize = SECUDP_NET_TO_HOST_32 (command -> connect.windowSize);

    if (windowSize < SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE)
      windowSize = SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
    if (windowSize > SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE)
      windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    verifyCommand.header.command = SECUDP_PROTOCOL_COMMAND_VERIFY_CONNECT | SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE;
    verifyCommand.header.channelID = 0xFF;
    verifyCommand.verifyConnect.outgoingPeerID = SECUDP_HOST_TO_NET_16 (peer -> incomingPeerID);
    verifyCommand.verifyConnect.incomingSessionID = incomingSessionID;
    verifyCommand.verifyConnect.outgoingSessionID = outgoingSessionID;
    verifyCommand.verifyConnect.mtu = SECUDP_HOST_TO_NET_32 (peer -> mtu);
    verifyCommand.verifyConnect.windowSize = SECUDP_HOST_TO_NET_32 (windowSize);
    verifyCommand.verifyConnect.channelCount = SECUDP_HOST_TO_NET_32 (channelCount);
    verifyCommand.verifyConnect.incomingBandwidth = SECUDP_HOST_TO_NET_32 (host -> incomingBandwidth);
    verifyCommand.verifyConnect.outgoingBandwidth = SECUDP_HOST_TO_NET_32 (host -> outgoingBandwidth);
    verifyCommand.verifyConnect.packetThrottleInterval = SECUDP_HOST_TO_NET_32 (peer -> packetThrottleInterval);
    verifyCommand.verifyConnect.packetThrottleAcceleration = SECUDP_HOST_TO_NET_32 (peer -> packetThrottleAcceleration);
    verifyCommand.verifyConnect.packetThrottleDeceleration = SECUDP_HOST_TO_NET_32 (peer -> packetThrottleDeceleration);
    verifyCommand.verifyConnect.connectID = peer -> connectID;
    memcpy(verifyCommand.verifyConnect.publicKx, peer -> secret -> kxPair.publicKx, SECUDP_KX_PUBLICBYTES);
    secudp_host_generate_signature(verifyCommand.verifyConnect.signature, verifyCommand.verifyConnect.publicKx, SECUDP_KX_PUBLICBYTES, host -> secret -> privateKey);
    memcpy(peer -> secret -> sessionPair.sendKey, secret.sessionPair.sendKey, SECUDP_SESSIONKEYBYTES);
    memcpy(peer -> secret -> sessionPair.recvKey, secret.sessionPair.recvKey, SECUDP_SESSIONKEYBYTES);

    secudp_peer_queue_outgoing_command (peer, & verifyCommand, NULL, 0, 0);

    return peer;
}

static int
secudp_protocol_handle_send_reliable (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint8 ** currentData)
{
    size_t dataLength;

    if (command -> header.channelID >= peer -> channelCount ||
        (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER))
      return -1;

    dataLength = SECUDP_NET_TO_HOST_16 (command -> sendReliable.dataLength);
    * currentData += dataLength;
    if (dataLength > host -> maximumPacketSize ||
        * currentData < host -> receivedData ||
        * currentData > & host -> receivedData [host -> receivedDataLength])
      return -1;

    if (secudp_peer_queue_incoming_command (peer, command, (const secudp_uint8 *) command + sizeof (SecUdpProtocolSendReliable), dataLength, SECUDP_PACKET_FLAG_RELIABLE, 0) == NULL)
      return -1;

    return 0;
}

static int
secudp_protocol_handle_send_unsequenced (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint8 ** currentData)
{
    secudp_uint32 unsequencedGroup, index;
    size_t dataLength;

    if (command -> header.channelID >= peer -> channelCount ||
        (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER))
      return -1;

    dataLength = SECUDP_NET_TO_HOST_16 (command -> sendUnsequenced.dataLength);
    * currentData += dataLength;
    if (dataLength > host -> maximumPacketSize ||
        * currentData < host -> receivedData ||
        * currentData > & host -> receivedData [host -> receivedDataLength])
      return -1; 

    unsequencedGroup = SECUDP_NET_TO_HOST_16 (command -> sendUnsequenced.unsequencedGroup);
    index = unsequencedGroup % SECUDP_PEER_UNSEQUENCED_WINDOW_SIZE;
   
    if (unsequencedGroup < peer -> incomingUnsequencedGroup)
      unsequencedGroup += 0x10000;

    if (unsequencedGroup >= (secudp_uint32) peer -> incomingUnsequencedGroup + SECUDP_PEER_FREE_UNSEQUENCED_WINDOWS * SECUDP_PEER_UNSEQUENCED_WINDOW_SIZE)
      return 0;

    unsequencedGroup &= 0xFFFF;

    if (unsequencedGroup - index != peer -> incomingUnsequencedGroup)
    {
        peer -> incomingUnsequencedGroup = unsequencedGroup - index;

        memset (peer -> unsequencedWindow, 0, sizeof (peer -> unsequencedWindow));
    }
    else
    if (peer -> unsequencedWindow [index / 32] & (1 << (index % 32)))
      return 0;
      
    if (secudp_peer_queue_incoming_command (peer, command, (const secudp_uint8 *) command + sizeof (SecUdpProtocolSendUnsequenced), dataLength, SECUDP_PACKET_FLAG_UNSEQUENCED, 0) == NULL)
      return -1;
   
    peer -> unsequencedWindow [index / 32] |= 1 << (index % 32);
 
    return 0;
}

static int
secudp_protocol_handle_send_unreliable (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint8 ** currentData)
{
    size_t dataLength;

    if (command -> header.channelID >= peer -> channelCount ||
        (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER))
      return -1;

    dataLength = SECUDP_NET_TO_HOST_16 (command -> sendUnreliable.dataLength);
    * currentData += dataLength;
    if (dataLength > host -> maximumPacketSize ||
        * currentData < host -> receivedData ||
        * currentData > & host -> receivedData [host -> receivedDataLength])
      return -1;

    if (secudp_peer_queue_incoming_command (peer, command, (const secudp_uint8 *) command + sizeof (SecUdpProtocolSendUnreliable), dataLength, 0, 0) == NULL)
      return -1;

    return 0;
}

static int
secudp_protocol_handle_send_fragment (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint8 ** currentData)
{
    secudp_uint32 fragmentNumber,
           fragmentCount,
           fragmentOffset,
           fragmentLength,
           startSequenceNumber,
           totalLength;
    SecUdpChannel * channel;
    secudp_uint16 startWindow, currentWindow;
    SecUdpListIterator currentCommand;
    SecUdpIncomingCommand * startCommand = NULL;

    if (command -> header.channelID >= peer -> channelCount ||
        (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER))
      return -1;

    fragmentLength = SECUDP_NET_TO_HOST_16 (command -> sendFragment.dataLength);
    * currentData += fragmentLength;
    if (fragmentLength > host -> maximumPacketSize ||
        * currentData < host -> receivedData ||
        * currentData > & host -> receivedData [host -> receivedDataLength])
      return -1;

    channel = & peer -> channels [command -> header.channelID];
    startSequenceNumber = SECUDP_NET_TO_HOST_16 (command -> sendFragment.startSequenceNumber);
    startWindow = startSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
    currentWindow = channel -> incomingReliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;

    if (startSequenceNumber < channel -> incomingReliableSequenceNumber)
      startWindow += SECUDP_PEER_RELIABLE_WINDOWS;

    if (startWindow < currentWindow || startWindow >= currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS - 1)
      return 0;

    fragmentNumber = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentNumber);
    fragmentCount = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentCount);
    fragmentOffset = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentOffset);
    totalLength = SECUDP_NET_TO_HOST_32 (command -> sendFragment.totalLength);
    
    if (fragmentCount > SECUDP_PROTOCOL_MAXIMUM_FRAGMENT_COUNT ||
        fragmentNumber >= fragmentCount ||
        totalLength > host -> maximumPacketSize ||
        fragmentOffset >= totalLength ||
        fragmentLength > totalLength - fragmentOffset)
      return -1;
 
    for (currentCommand = secudp_list_previous (secudp_list_end (& channel -> incomingReliableCommands));
         currentCommand != secudp_list_end (& channel -> incomingReliableCommands);
         currentCommand = secudp_list_previous (currentCommand))
    {
       SecUdpIncomingCommand * incomingCommand = (SecUdpIncomingCommand *) currentCommand;

       if (startSequenceNumber >= channel -> incomingReliableSequenceNumber)
       {
          if (incomingCommand -> reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
            continue;
       }
       else
       if (incomingCommand -> reliableSequenceNumber >= channel -> incomingReliableSequenceNumber)
         break;

       if (incomingCommand -> reliableSequenceNumber <= startSequenceNumber)
       {
          if (incomingCommand -> reliableSequenceNumber < startSequenceNumber)
            break;
        
          if ((incomingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK) != SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT ||
              totalLength != incomingCommand -> packet -> dataLength ||
              fragmentCount != incomingCommand -> fragmentCount)
            return -1;

          startCommand = incomingCommand;
          break;
       }
    }
 
    if (startCommand == NULL)
    {
       SecUdpProtocol hostCommand = * command;

       hostCommand.header.reliableSequenceNumber = startSequenceNumber;

       startCommand = secudp_peer_queue_incoming_command (peer, & hostCommand, NULL, totalLength, SECUDP_PACKET_FLAG_RELIABLE, fragmentCount);
       if (startCommand == NULL)
         return -1;
    }
    
    if ((startCommand -> fragments [fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0)
    {
       -- startCommand -> fragmentsRemaining;

       startCommand -> fragments [fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

       if (fragmentOffset + fragmentLength > startCommand -> packet -> dataLength)
         fragmentLength = startCommand -> packet -> dataLength - fragmentOffset;

       memcpy (startCommand -> packet -> data + fragmentOffset,
               (secudp_uint8 *) command + sizeof (SecUdpProtocolSendFragment),
               fragmentLength);

        if (startCommand -> fragmentsRemaining <= 0)
          secudp_peer_dispatch_incoming_reliable_commands (peer, channel, NULL);
    }

    return 0;
}

static int
secudp_protocol_handle_send_unreliable_fragment (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command, secudp_uint8 ** currentData)
{
    secudp_uint32 fragmentNumber,
           fragmentCount,
           fragmentOffset,
           fragmentLength,
           reliableSequenceNumber,
           startSequenceNumber,
           totalLength;
    secudp_uint16 reliableWindow, currentWindow;
    SecUdpChannel * channel;
    SecUdpListIterator currentCommand;
    SecUdpIncomingCommand * startCommand = NULL;

    if (command -> header.channelID >= peer -> channelCount ||
        (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER))
      return -1;

    fragmentLength = SECUDP_NET_TO_HOST_16 (command -> sendFragment.dataLength);
    * currentData += fragmentLength;
    if (fragmentLength > host -> maximumPacketSize ||
        * currentData < host -> receivedData ||
        * currentData > & host -> receivedData [host -> receivedDataLength])
      return -1;

    channel = & peer -> channels [command -> header.channelID];
    reliableSequenceNumber = command -> header.reliableSequenceNumber;
    startSequenceNumber = SECUDP_NET_TO_HOST_16 (command -> sendFragment.startSequenceNumber);

    reliableWindow = reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
    currentWindow = channel -> incomingReliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;

    if (reliableSequenceNumber < channel -> incomingReliableSequenceNumber)
      reliableWindow += SECUDP_PEER_RELIABLE_WINDOWS;

    if (reliableWindow < currentWindow || reliableWindow >= currentWindow + SECUDP_PEER_FREE_RELIABLE_WINDOWS - 1)
      return 0;

    if (reliableSequenceNumber == channel -> incomingReliableSequenceNumber &&
        startSequenceNumber <= channel -> incomingUnreliableSequenceNumber)
      return 0;

    fragmentNumber = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentNumber);
    fragmentCount = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentCount);
    fragmentOffset = SECUDP_NET_TO_HOST_32 (command -> sendFragment.fragmentOffset);
    totalLength = SECUDP_NET_TO_HOST_32 (command -> sendFragment.totalLength);

    if (fragmentCount > SECUDP_PROTOCOL_MAXIMUM_FRAGMENT_COUNT ||
        fragmentNumber >= fragmentCount ||
        totalLength > host -> maximumPacketSize ||
        fragmentOffset >= totalLength ||
        fragmentLength > totalLength - fragmentOffset)
      return -1;

    for (currentCommand = secudp_list_previous (secudp_list_end (& channel -> incomingUnreliableCommands));
         currentCommand != secudp_list_end (& channel -> incomingUnreliableCommands);
         currentCommand = secudp_list_previous (currentCommand))
    {
       SecUdpIncomingCommand * incomingCommand = (SecUdpIncomingCommand *) currentCommand;

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

       if (incomingCommand -> unreliableSequenceNumber <= startSequenceNumber)
       {
          if (incomingCommand -> unreliableSequenceNumber < startSequenceNumber)
            break;

          if ((incomingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK) != SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT ||
              totalLength != incomingCommand -> packet -> dataLength ||
              fragmentCount != incomingCommand -> fragmentCount)
            return -1;

          startCommand = incomingCommand;
          break;
       }
    }

    if (startCommand == NULL)
    {
       startCommand = secudp_peer_queue_incoming_command (peer, command, NULL, totalLength, SECUDP_PACKET_FLAG_UNRELIABLE_FRAGMENT, fragmentCount);
       if (startCommand == NULL)
         return -1;
    }

    if ((startCommand -> fragments [fragmentNumber / 32] & (1 << (fragmentNumber % 32))) == 0)
    {
       -- startCommand -> fragmentsRemaining;

       startCommand -> fragments [fragmentNumber / 32] |= (1 << (fragmentNumber % 32));

       if (fragmentOffset + fragmentLength > startCommand -> packet -> dataLength)
         fragmentLength = startCommand -> packet -> dataLength - fragmentOffset;

       memcpy (startCommand -> packet -> data + fragmentOffset,
               (secudp_uint8 *) command + sizeof (SecUdpProtocolSendFragment),
               fragmentLength);

        if (startCommand -> fragmentsRemaining <= 0)
          secudp_peer_dispatch_incoming_unreliable_commands (peer, channel, NULL);
    }

    return 0;
}

static int
secudp_protocol_handle_ping (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
      return -1;

    return 0;
}

static int
secudp_protocol_handle_bandwidth_limit (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
      return -1;

    if (peer -> incomingBandwidth != 0)
      -- host -> bandwidthLimitedPeers;

    peer -> incomingBandwidth = SECUDP_NET_TO_HOST_32 (command -> bandwidthLimit.incomingBandwidth);
    peer -> outgoingBandwidth = SECUDP_NET_TO_HOST_32 (command -> bandwidthLimit.outgoingBandwidth);

    if (peer -> incomingBandwidth != 0)
      ++ host -> bandwidthLimitedPeers;

    if (peer -> incomingBandwidth == 0 && host -> outgoingBandwidth == 0)
      peer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;
    else
    if (peer -> incomingBandwidth == 0 || host -> outgoingBandwidth == 0)
      peer -> windowSize = (SECUDP_MAX (peer -> incomingBandwidth, host -> outgoingBandwidth) /
                             SECUDP_PEER_WINDOW_SIZE_SCALE) * SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
      peer -> windowSize = (SECUDP_MIN (peer -> incomingBandwidth, host -> outgoingBandwidth) /
                             SECUDP_PEER_WINDOW_SIZE_SCALE) * SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (peer -> windowSize < SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE)
      peer -> windowSize = SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;
    else
    if (peer -> windowSize > SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE)
      peer -> windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    return 0;
}

static int
secudp_protocol_handle_throttle_configure (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
      return -1;

    peer -> packetThrottleInterval = SECUDP_NET_TO_HOST_32 (command -> throttleConfigure.packetThrottleInterval);
    peer -> packetThrottleAcceleration = SECUDP_NET_TO_HOST_32 (command -> throttleConfigure.packetThrottleAcceleration);
    peer -> packetThrottleDeceleration = SECUDP_NET_TO_HOST_32 (command -> throttleConfigure.packetThrottleDeceleration);

    return 0;
}

static int
secudp_protocol_handle_disconnect (SecUdpHost * host, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    if (peer -> state == SECUDP_PEER_STATE_DISCONNECTED || peer -> state == SECUDP_PEER_STATE_ZOMBIE || peer -> state == SECUDP_PEER_STATE_ACKNOWLEDGING_DISCONNECT)
      return 0;

    secudp_peer_reset_queues (peer);
    if(peer -> secret != NULL)
    {
        secudp_free(peer -> secret);
        peer -> secret = NULL;
    }

    if (peer -> state == SECUDP_PEER_STATE_CONNECTION_SUCCEEDED || peer -> state == SECUDP_PEER_STATE_DISCONNECTING || peer -> state == SECUDP_PEER_STATE_CONNECTING)
        secudp_protocol_dispatch_state (host, peer, SECUDP_PEER_STATE_ZOMBIE);
    else
    if (peer -> state != SECUDP_PEER_STATE_CONNECTED && peer -> state != SECUDP_PEER_STATE_DISCONNECT_LATER)
    {
        if (peer -> state == SECUDP_PEER_STATE_CONNECTION_PENDING) host -> recalculateBandwidthLimits = 1;

        secudp_peer_reset (peer);
    }
    else
    if (command -> header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
      secudp_protocol_change_state (host, peer, SECUDP_PEER_STATE_ACKNOWLEDGING_DISCONNECT);
    else
      secudp_protocol_dispatch_state (host, peer, SECUDP_PEER_STATE_ZOMBIE);

    if (peer -> state != SECUDP_PEER_STATE_DISCONNECTED)
      peer -> eventData = SECUDP_NET_TO_HOST_32 (command -> disconnect.data);

    return 0;
}

static int
secudp_protocol_handle_acknowledge (SecUdpHost * host, SecUdpEvent * event, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    secudp_uint32 roundTripTime,
           receivedSentTime,
           receivedReliableSequenceNumber;
    SecUdpProtocolCommand commandNumber;

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECTED || peer -> state == SECUDP_PEER_STATE_ZOMBIE)
      return 0;

    receivedSentTime = SECUDP_NET_TO_HOST_16 (command -> acknowledge.receivedSentTime);
    receivedSentTime |= host -> serviceTime & 0xFFFF0000;
    if ((receivedSentTime & 0x8000) > (host -> serviceTime & 0x8000))
        receivedSentTime -= 0x10000;

    if (SECUDP_TIME_LESS (host -> serviceTime, receivedSentTime))
      return 0;

    roundTripTime = SECUDP_TIME_DIFFERENCE (host -> serviceTime, receivedSentTime);
    roundTripTime = SECUDP_MAX (roundTripTime, 1);

    if (peer -> lastReceiveTime > 0)
    {
       secudp_peer_throttle (peer, roundTripTime);

       peer -> roundTripTimeVariance -= peer -> roundTripTimeVariance / 4;

       if (roundTripTime >= peer -> roundTripTime)
       {
          secudp_uint32 diff = roundTripTime - peer -> roundTripTime;
          peer -> roundTripTimeVariance += diff / 4;
          peer -> roundTripTime += diff / 8;
       }
       else
       {
          secudp_uint32 diff = peer -> roundTripTime - roundTripTime;
          peer -> roundTripTimeVariance += diff / 4;
          peer -> roundTripTime -= diff / 8;
       }
    }
    else
    {
       peer -> roundTripTime = roundTripTime;
       peer -> roundTripTimeVariance = (roundTripTime + 1) / 2;
    }

    if (peer -> roundTripTime < peer -> lowestRoundTripTime)
      peer -> lowestRoundTripTime = peer -> roundTripTime;

    if (peer -> roundTripTimeVariance > peer -> highestRoundTripTimeVariance)
      peer -> highestRoundTripTimeVariance = peer -> roundTripTimeVariance;

    if (peer -> packetThrottleEpoch == 0 ||
        SECUDP_TIME_DIFFERENCE (host -> serviceTime, peer -> packetThrottleEpoch) >= peer -> packetThrottleInterval)
    {
        peer -> lastRoundTripTime = peer -> lowestRoundTripTime;
        peer -> lastRoundTripTimeVariance = SECUDP_MAX (peer -> highestRoundTripTimeVariance, 1);
        peer -> lowestRoundTripTime = peer -> roundTripTime;
        peer -> highestRoundTripTimeVariance = peer -> roundTripTimeVariance;
        peer -> packetThrottleEpoch = host -> serviceTime;
    }

    peer -> lastReceiveTime = SECUDP_MAX (host -> serviceTime, 1);
    peer -> earliestTimeout = 0;

    receivedReliableSequenceNumber = SECUDP_NET_TO_HOST_16 (command -> acknowledge.receivedReliableSequenceNumber);

    commandNumber = secudp_protocol_remove_sent_reliable_command (peer, receivedReliableSequenceNumber, command -> header.channelID);

    switch (peer -> state)
    {
    case SECUDP_PEER_STATE_ACKNOWLEDGING_CONNECT:
       if (commandNumber != SECUDP_PROTOCOL_COMMAND_VERIFY_CONNECT)
         return -1;

       secudp_protocol_notify_connect (host, peer, event);
       break;

    case SECUDP_PEER_STATE_DISCONNECTING:
       if (commandNumber != SECUDP_PROTOCOL_COMMAND_DISCONNECT)
         return -1;

       secudp_protocol_notify_disconnect (host, peer, event);
       break;

    case SECUDP_PEER_STATE_DISCONNECT_LATER:
       if (secudp_list_empty (& peer -> outgoingCommands) &&
           secudp_list_empty (& peer -> sentReliableCommands))
         secudp_peer_disconnect (peer, peer -> eventData);
       break;

    default:
       break;
    }
   
    return 0;
}

static int
secudp_protocol_handle_verify_connect (SecUdpHost * host, SecUdpEvent * event, SecUdpPeer * peer, const SecUdpProtocol * command)
{
    secudp_uint32 mtu, windowSize;
    size_t channelCount;
    SecUdpPeerSecret secret;

    if (peer -> state != SECUDP_PEER_STATE_CONNECTING)
      return 0;

    channelCount = SECUDP_NET_TO_HOST_32 (command -> verifyConnect.channelCount);

    /*
     *  Additionally check if session keys can be generated from the secret key
     *  exchange pair and the public key received. Extension of ENet.
     */
    if (channelCount < SECUDP_PROTOCOL_MINIMUM_CHANNEL_COUNT || channelCount > SECUDP_PROTOCOL_MAXIMUM_CHANNEL_COUNT ||
        SECUDP_NET_TO_HOST_32 (command -> verifyConnect.packetThrottleInterval) != peer -> packetThrottleInterval ||
        SECUDP_NET_TO_HOST_32 (command -> verifyConnect.packetThrottleAcceleration) != peer -> packetThrottleAcceleration ||
        SECUDP_NET_TO_HOST_32 (command -> verifyConnect.packetThrottleDeceleration) != peer -> packetThrottleDeceleration ||
        command -> verifyConnect.connectID != peer -> connectID || 
        secudp_peer_gen_session_keys(secret.sessionPair.sendKey, secret.sessionPair.recvKey, peer -> secret -> kxPair.publicKx, peer -> secret -> kxPair.privateKx, command -> verifyConnect.publicKx) ||
        secudp_host_verify_signature(command -> verifyConnect.signature, command -> verifyConnect.publicKx, SECUDP_KX_PUBLICBYTES, host -> secret -> publicKey))
    {
        peer -> eventData = 0;
        secudp_protocol_dispatch_state (host, peer, SECUDP_PEER_STATE_ZOMBIE);

        return -1;
    }

    memcpy(peer -> secret -> sessionPair.sendKey, secret.sessionPair.sendKey, SECUDP_SESSIONKEYBYTES);
    memcpy(peer -> secret -> sessionPair.recvKey, secret.sessionPair.recvKey, SECUDP_SESSIONKEYBYTES);
    secudp_protocol_remove_sent_reliable_command (peer, 1, 0xFF);
    
    if (channelCount < peer -> channelCount)
      peer -> channelCount = channelCount;

    peer -> outgoingPeerID = SECUDP_NET_TO_HOST_16 (command -> verifyConnect.outgoingPeerID);
    peer -> incomingSessionID = command -> verifyConnect.incomingSessionID;
    peer -> outgoingSessionID = command -> verifyConnect.outgoingSessionID;

    mtu = SECUDP_NET_TO_HOST_32 (command -> verifyConnect.mtu);

    if (mtu < SECUDP_PROTOCOL_MINIMUM_MTU)
      mtu = SECUDP_PROTOCOL_MINIMUM_MTU;
    else 
    if (mtu > SECUDP_PROTOCOL_MAXIMUM_MTU)
      mtu = SECUDP_PROTOCOL_MAXIMUM_MTU;

    if (mtu < peer -> mtu)
      peer -> mtu = mtu;

    windowSize = SECUDP_NET_TO_HOST_32 (command -> verifyConnect.windowSize);

    if (windowSize < SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE)
      windowSize = SECUDP_PROTOCOL_MINIMUM_WINDOW_SIZE;

    if (windowSize > SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE)
      windowSize = SECUDP_PROTOCOL_MAXIMUM_WINDOW_SIZE;

    if (windowSize < peer -> windowSize)
      peer -> windowSize = windowSize;

    peer -> incomingBandwidth = SECUDP_NET_TO_HOST_32 (command -> verifyConnect.incomingBandwidth);
    peer -> outgoingBandwidth = SECUDP_NET_TO_HOST_32 (command -> verifyConnect.outgoingBandwidth);

    secudp_protocol_notify_connect (host, peer, event);

    return 0;
}

static int
secudp_protocol_handle_incoming_commands (SecUdpHost * host, SecUdpEvent * event)
{
    SecUdpProtocolHeader * header;
    SecUdpProtocol * command;
    SecUdpPeer * peer;
    secudp_uint8 * currentData;
    size_t headerSize;
    secudp_uint16 peerID, flags;
    secudp_uint8 sessionID;

    if (host -> receivedDataLength < (size_t) & ((SecUdpProtocolHeader *) 0) -> sentTime)
      return 0;

    header = (SecUdpProtocolHeader *) host -> receivedData;

    peerID = SECUDP_NET_TO_HOST_16 (header -> peerID);
    sessionID = (peerID & SECUDP_PROTOCOL_HEADER_SESSION_MASK) >> SECUDP_PROTOCOL_HEADER_SESSION_SHIFT;
    flags = peerID & SECUDP_PROTOCOL_HEADER_FLAG_MASK;
    peerID &= ~ (SECUDP_PROTOCOL_HEADER_FLAG_MASK | SECUDP_PROTOCOL_HEADER_SESSION_MASK);

    headerSize = (flags & SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME ? sizeof (SecUdpProtocolHeader) : (size_t) & ((SecUdpProtocolHeader *) 0) -> sentTime);
    if (host -> checksum != NULL)
      headerSize += sizeof (secudp_uint32);

    if (peerID == SECUDP_PROTOCOL_MAXIMUM_PEER_ID)
      peer = NULL;
    else
    if (peerID >= host -> peerCount)
      return 0;
    else
    {
       peer = & host -> peers [peerID];

       if (peer -> state == SECUDP_PEER_STATE_DISCONNECTED ||
           peer -> state == SECUDP_PEER_STATE_ZOMBIE ||
           ((host -> receivedAddress.host != peer -> address.host ||
             host -> receivedAddress.port != peer -> address.port) &&
             peer -> address.host != SECUDP_HOST_BROADCAST) ||
           (peer -> outgoingPeerID < SECUDP_PROTOCOL_MAXIMUM_PEER_ID &&
            sessionID != peer -> incomingSessionID))
         return 0;
    }
 
    if (flags & SECUDP_PROTOCOL_HEADER_FLAG_COMPRESSED)
    {
        size_t originalSize;
        if (host -> compressor.context == NULL || host -> compressor.decompress == NULL)
          return 0;

        originalSize = host -> compressor.decompress (host -> compressor.context,
                                    host -> receivedData + headerSize, 
                                    host -> receivedDataLength - headerSize, 
                                    host -> packetData [1] + headerSize, 
                                    sizeof (host -> packetData [1]) - headerSize);
        if (originalSize <= 0 || originalSize > sizeof (host -> packetData [1]) - headerSize)
          return 0;

        memcpy (host -> packetData [1], header, headerSize);
        host -> receivedData = host -> packetData [1];
        host -> receivedDataLength = headerSize + originalSize;
    }

    if (host -> checksum != NULL)
    {
        secudp_uint32 * checksum = (secudp_uint32 *) & host -> receivedData [headerSize - sizeof (secudp_uint32)],
                    desiredChecksum = * checksum;
        SecUdpBuffer buffer;

        * checksum = peer != NULL ? peer -> connectID : 0;

        buffer.data = host -> receivedData;
        buffer.dataLength = host -> receivedDataLength;

        if (host -> checksum (& buffer, 1) != desiredChecksum)
          return 0;
    }
       
    if (peer != NULL)
    {
       peer -> address.host = host -> receivedAddress.host;
       peer -> address.port = host -> receivedAddress.port;
       peer -> incomingDataTotal += host -> receivedDataLength;
    }
    
    currentData = host -> receivedData + headerSize;
  
    while (currentData < & host -> receivedData [host -> receivedDataLength])
    {
       secudp_uint8 commandNumber;
       size_t commandSize;

       command = (SecUdpProtocol *) currentData;

       if (currentData + sizeof (SecUdpProtocolCommandHeader) > & host -> receivedData [host -> receivedDataLength])
         break;

       commandNumber = command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK;
       if (commandNumber >= SECUDP_PROTOCOL_COMMAND_COUNT) 
         break;
       
       commandSize = commandSizes [commandNumber];
       if (commandSize == 0 || currentData + commandSize > & host -> receivedData [host -> receivedDataLength])
         break;

       currentData += commandSize;

       if (peer == NULL && commandNumber != SECUDP_PROTOCOL_COMMAND_CONNECT)
         break;
         
       command -> header.reliableSequenceNumber = SECUDP_NET_TO_HOST_16 (command -> header.reliableSequenceNumber);

       switch (commandNumber)
       {
       case SECUDP_PROTOCOL_COMMAND_ACKNOWLEDGE:
          if (secudp_protocol_handle_acknowledge (host, event, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_CONNECT:
          if (peer != NULL)
            goto commandError;
          peer = secudp_protocol_handle_connect (host, header, command);
          if (peer == NULL)
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_VERIFY_CONNECT:
          if (secudp_protocol_handle_verify_connect (host, event, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_DISCONNECT:
          if (secudp_protocol_handle_disconnect (host, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_PING:
          if (secudp_protocol_handle_ping (host, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_SEND_RELIABLE:
          if (secudp_protocol_handle_send_reliable (host, peer, command, & currentData))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE:
          if (secudp_protocol_handle_send_unreliable (host, peer, command, & currentData))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_SEND_UNSEQUENCED:
          if (secudp_protocol_handle_send_unsequenced (host, peer, command, & currentData))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_SEND_FRAGMENT:
          if (secudp_protocol_handle_send_fragment (host, peer, command, & currentData))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_BANDWIDTH_LIMIT:
          if (secudp_protocol_handle_bandwidth_limit (host, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_THROTTLE_CONFIGURE:
          if (secudp_protocol_handle_throttle_configure (host, peer, command))
            goto commandError;
          break;

       case SECUDP_PROTOCOL_COMMAND_SEND_UNRELIABLE_FRAGMENT:
          if (secudp_protocol_handle_send_unreliable_fragment (host, peer, command, & currentData))
            goto commandError;
          break;

       default:
          goto commandError;
       }

       if (peer != NULL &&
           (command -> header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE) != 0)
       {
           secudp_uint16 sentTime;

           if (! (flags & SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME))
             break;

           sentTime = SECUDP_NET_TO_HOST_16 (header -> sentTime);

           switch (peer -> state)
           {
           case SECUDP_PEER_STATE_DISCONNECTING:
           case SECUDP_PEER_STATE_ACKNOWLEDGING_CONNECT:
           case SECUDP_PEER_STATE_DISCONNECTED:
           case SECUDP_PEER_STATE_ZOMBIE:
              break;

           case SECUDP_PEER_STATE_ACKNOWLEDGING_DISCONNECT:
              if ((command -> header.command & SECUDP_PROTOCOL_COMMAND_MASK) == SECUDP_PROTOCOL_COMMAND_DISCONNECT)
                secudp_peer_queue_acknowledgement (peer, command, sentTime);
              break;

           default:   
              secudp_peer_queue_acknowledgement (peer, command, sentTime);        
              break;
           }
       }
    }

commandError:
    if (event != NULL && event -> type != SECUDP_EVENT_TYPE_NONE)
      return 1;

    return 0;
}
 
static int
secudp_protocol_receive_incoming_commands (SecUdpHost * host, SecUdpEvent * event)
{
    int packets;

    for (packets = 0; packets < 256; ++ packets)
    {
       int receivedLength;
       SecUdpBuffer buffer;

       buffer.data = host -> packetData [0];
       buffer.dataLength = sizeof (host -> packetData [0]);

       receivedLength = secudp_socket_receive (host -> socket,
                                             & host -> receivedAddress,
                                             & buffer,
                                             1);

       if (receivedLength < 0)
         return -1;

       if (receivedLength == 0)
         return 0;

       host -> receivedData = host -> packetData [0];
       host -> receivedDataLength = receivedLength;
      
       host -> totalReceivedData += receivedLength;
       host -> totalReceivedPackets ++;

       if (host -> intercept != NULL)
       {
          switch (host -> intercept (host, event))
          {
          case 1:
             if (event != NULL && event -> type != SECUDP_EVENT_TYPE_NONE)
               return 1;

             continue;
          
          case -1:
             return -1;
        
          default:
             break;
          }
       }
        
       switch (secudp_protocol_handle_incoming_commands (host, event))
       {
       case 1:
          return 1;
       
       case -1:
          return -1;

       default:
          break;
       }
    }

    return 0;
}

static void
secudp_protocol_send_acknowledgements (SecUdpHost * host, SecUdpPeer * peer)
{
    SecUdpProtocol * command = & host -> commands [host -> commandCount];
    SecUdpBuffer * buffer = & host -> buffers [host -> bufferCount];
    SecUdpAcknowledgement * acknowledgement;
    SecUdpListIterator currentAcknowledgement;
    secudp_uint16 reliableSequenceNumber;
 
    currentAcknowledgement = secudp_list_begin (& peer -> acknowledgements);
         
    while (currentAcknowledgement != secudp_list_end (& peer -> acknowledgements))
    {
       if (command >= & host -> commands [sizeof (host -> commands) / sizeof (SecUdpProtocol)] ||
           buffer >= & host -> buffers [sizeof (host -> buffers) / sizeof (SecUdpBuffer)] ||
           peer -> mtu - host -> packetSize < sizeof (SecUdpProtocolAcknowledge))
       {
          host -> continueSending = 1;

          break;
       }

       acknowledgement = (SecUdpAcknowledgement *) currentAcknowledgement;
 
       currentAcknowledgement = secudp_list_next (currentAcknowledgement);

       buffer -> data = command;
       buffer -> dataLength = sizeof (SecUdpProtocolAcknowledge);

       host -> packetSize += buffer -> dataLength;

       reliableSequenceNumber = SECUDP_HOST_TO_NET_16 (acknowledgement -> command.header.reliableSequenceNumber);
  
       command -> header.command = SECUDP_PROTOCOL_COMMAND_ACKNOWLEDGE;
       command -> header.channelID = acknowledgement -> command.header.channelID;
       command -> header.reliableSequenceNumber = reliableSequenceNumber;
       command -> acknowledge.receivedReliableSequenceNumber = reliableSequenceNumber;
       command -> acknowledge.receivedSentTime = SECUDP_HOST_TO_NET_16 (acknowledgement -> sentTime);
  
       if ((acknowledgement -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK) == SECUDP_PROTOCOL_COMMAND_DISCONNECT)
         secudp_protocol_dispatch_state (host, peer, SECUDP_PEER_STATE_ZOMBIE);

       secudp_list_remove (& acknowledgement -> acknowledgementList);
       secudp_free (acknowledgement);

       ++ command;
       ++ buffer;
    }

    host -> commandCount = command - host -> commands;
    host -> bufferCount = buffer - host -> buffers;
}

static int
secudp_protocol_check_timeouts (SecUdpHost * host, SecUdpPeer * peer, SecUdpEvent * event)
{
    SecUdpOutgoingCommand * outgoingCommand;
    SecUdpListIterator currentCommand, insertPosition;

    currentCommand = secudp_list_begin (& peer -> sentReliableCommands);
    insertPosition = secudp_list_begin (& peer -> outgoingCommands);

    while (currentCommand != secudp_list_end (& peer -> sentReliableCommands))
    {
       outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;

       currentCommand = secudp_list_next (currentCommand);

       if (SECUDP_TIME_DIFFERENCE (host -> serviceTime, outgoingCommand -> sentTime) < outgoingCommand -> roundTripTimeout)
         continue;

       if (peer -> earliestTimeout == 0 ||
           SECUDP_TIME_LESS (outgoingCommand -> sentTime, peer -> earliestTimeout))
         peer -> earliestTimeout = outgoingCommand -> sentTime;

       if (peer -> earliestTimeout != 0 &&
             (SECUDP_TIME_DIFFERENCE (host -> serviceTime, peer -> earliestTimeout) >= peer -> timeoutMaximum ||
               (outgoingCommand -> roundTripTimeout >= outgoingCommand -> roundTripTimeoutLimit &&
                 SECUDP_TIME_DIFFERENCE (host -> serviceTime, peer -> earliestTimeout) >= peer -> timeoutMinimum)))
       {
          secudp_protocol_notify_disconnect (host, peer, event);

          return 1;
       }

       if (outgoingCommand -> packet != NULL)
         peer -> reliableDataInTransit -= outgoingCommand -> fragmentLength;
          
       ++ peer -> packetsLost;

       outgoingCommand -> roundTripTimeout *= 2;

       secudp_list_insert (insertPosition, secudp_list_remove (& outgoingCommand -> outgoingCommandList));

       if (currentCommand == secudp_list_begin (& peer -> sentReliableCommands) &&
           ! secudp_list_empty (& peer -> sentReliableCommands))
       {
          outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;

          peer -> nextTimeout = outgoingCommand -> sentTime + outgoingCommand -> roundTripTimeout;
       }
    }
    
    return 0;
}

static int
secudp_protocol_check_outgoing_commands (SecUdpHost * host, SecUdpPeer * peer)
{
    SecUdpProtocol * command = & host -> commands [host -> commandCount];
    SecUdpBuffer * buffer = & host -> buffers [host -> bufferCount];
    SecUdpOutgoingCommand * outgoingCommand;
    SecUdpListIterator currentCommand;
    SecUdpChannel *channel;
    secudp_uint16 reliableWindow;
    size_t commandSize;
    int windowExceeded = 0, windowWrap = 0, canPing = 1;

    currentCommand = secudp_list_begin (& peer -> outgoingCommands);
    
    while (currentCommand != secudp_list_end (& peer -> outgoingCommands))
    {
       outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;

       if (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
       {
          channel = outgoingCommand -> command.header.channelID < peer -> channelCount ? & peer -> channels [outgoingCommand -> command.header.channelID] : NULL;
          reliableWindow = outgoingCommand -> reliableSequenceNumber / SECUDP_PEER_RELIABLE_WINDOW_SIZE;
          if (channel != NULL)
          {
             if (! windowWrap &&      
                  outgoingCommand -> sendAttempts < 1 && 
                  ! (outgoingCommand -> reliableSequenceNumber % SECUDP_PEER_RELIABLE_WINDOW_SIZE) &&
                  (channel -> reliableWindows [(reliableWindow + SECUDP_PEER_RELIABLE_WINDOWS - 1) % SECUDP_PEER_RELIABLE_WINDOWS] >= SECUDP_PEER_RELIABLE_WINDOW_SIZE ||
                    channel -> usedReliableWindows & ((((1 << (SECUDP_PEER_FREE_RELIABLE_WINDOWS + 1)) - 1) << reliableWindow) |
                      (((1 << (SECUDP_PEER_FREE_RELIABLE_WINDOWS + 1)) - 1) >> (SECUDP_PEER_RELIABLE_WINDOWS - reliableWindow)))))
                windowWrap = 1;
             if (windowWrap)
             {
                currentCommand = secudp_list_next (currentCommand);
 
                continue;
             }
          }
 
          if (outgoingCommand -> packet != NULL)
          {
             if (! windowExceeded)
             {
                secudp_uint32 windowSize = (peer -> packetThrottle * peer -> windowSize) / SECUDP_PEER_PACKET_THROTTLE_SCALE;
             
                if (peer -> reliableDataInTransit + outgoingCommand -> fragmentLength > SECUDP_MAX (windowSize, peer -> mtu))
                  windowExceeded = 1;
             }
             if (windowExceeded)
             {
                currentCommand = secudp_list_next (currentCommand);

                continue;
             }
          }

          canPing = 0;
       }

       commandSize = commandSizes [outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_MASK];
       if (command >= & host -> commands [sizeof (host -> commands) / sizeof (SecUdpProtocol)] ||
           buffer + 1 >= & host -> buffers [sizeof (host -> buffers) / sizeof (SecUdpBuffer)] ||
           peer -> mtu - host -> packetSize < commandSize ||
           (outgoingCommand -> packet != NULL && 
             (secudp_uint16) (peer -> mtu - host -> packetSize) < (secudp_uint16) (commandSize + outgoingCommand -> fragmentLength)))
       {
          host -> continueSending = 1;
          
          break;
       }

       currentCommand = secudp_list_next (currentCommand);

       if (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE)
       {
          if (channel != NULL && outgoingCommand -> sendAttempts < 1)
          {
             channel -> usedReliableWindows |= 1 << reliableWindow;
             ++ channel -> reliableWindows [reliableWindow];
          }

          ++ outgoingCommand -> sendAttempts;
 
          if (outgoingCommand -> roundTripTimeout == 0)
          {
             outgoingCommand -> roundTripTimeout = peer -> roundTripTime + 4 * peer -> roundTripTimeVariance;
             outgoingCommand -> roundTripTimeoutLimit = peer -> timeoutLimit * outgoingCommand -> roundTripTimeout;
          }

          if (secudp_list_empty (& peer -> sentReliableCommands))
            peer -> nextTimeout = host -> serviceTime + outgoingCommand -> roundTripTimeout;

          secudp_list_insert (secudp_list_end (& peer -> sentReliableCommands),
                            secudp_list_remove (& outgoingCommand -> outgoingCommandList));

          outgoingCommand -> sentTime = host -> serviceTime;

          host -> headerFlags |= SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME;

          peer -> reliableDataInTransit += outgoingCommand -> fragmentLength;
       }
       else
       {
          if (outgoingCommand -> packet != NULL && outgoingCommand -> fragmentOffset == 0)
          {
             peer -> packetThrottleCounter += SECUDP_PEER_PACKET_THROTTLE_COUNTER;
             peer -> packetThrottleCounter %= SECUDP_PEER_PACKET_THROTTLE_SCALE;

             if (peer -> packetThrottleCounter > peer -> packetThrottle)
             {
                secudp_uint16 reliableSequenceNumber = outgoingCommand -> reliableSequenceNumber,
                            unreliableSequenceNumber = outgoingCommand -> unreliableSequenceNumber;
                for (;;)
                {
                   -- outgoingCommand -> packet -> referenceCount;

                   if (outgoingCommand -> packet -> referenceCount == 0)
                     secudp_packet_destroy (outgoingCommand -> packet);

                   secudp_list_remove (& outgoingCommand -> outgoingCommandList);
                   secudp_free (outgoingCommand);

                   if (currentCommand == secudp_list_end (& peer -> outgoingCommands))
                     break;

                   outgoingCommand = (SecUdpOutgoingCommand *) currentCommand;
                   if (outgoingCommand -> reliableSequenceNumber != reliableSequenceNumber ||
                       outgoingCommand -> unreliableSequenceNumber != unreliableSequenceNumber)
                     break;

                   currentCommand = secudp_list_next (currentCommand);
                }

                continue;
             }
          }

          secudp_list_remove (& outgoingCommand -> outgoingCommandList);

          if (outgoingCommand -> packet != NULL)
            secudp_list_insert (secudp_list_end (& peer -> sentUnreliableCommands), outgoingCommand);
       }

       buffer -> data = command;
       buffer -> dataLength = commandSize;

       host -> packetSize += buffer -> dataLength;

       * command = outgoingCommand -> command;

       if (outgoingCommand -> packet != NULL)
       {
          ++ buffer;
          
          buffer -> data = outgoingCommand -> packet -> ciphertext + outgoingCommand -> fragmentOffset;
          buffer -> dataLength = outgoingCommand -> fragmentLength;

          host -> packetSize += outgoingCommand -> fragmentLength;
       }
       else
       if (! (outgoingCommand -> command.header.command & SECUDP_PROTOCOL_COMMAND_FLAG_ACKNOWLEDGE))
         secudp_free (outgoingCommand);

       ++ peer -> packetsSent;
        
       ++ command;
       ++ buffer;
    }

    host -> commandCount = command - host -> commands;
    host -> bufferCount = buffer - host -> buffers;

    if (peer -> state == SECUDP_PEER_STATE_DISCONNECT_LATER &&
        secudp_list_empty (& peer -> outgoingCommands) &&
        secudp_list_empty (& peer -> sentReliableCommands) &&
        secudp_list_empty (& peer -> sentUnreliableCommands))
      secudp_peer_disconnect (peer, peer -> eventData);

    return canPing;
}

static int
secudp_protocol_send_outgoing_commands (SecUdpHost * host, SecUdpEvent * event, int checkForTimeouts)
{
    secudp_uint8 headerData [sizeof (SecUdpProtocolHeader) + sizeof (secudp_uint32)];
    SecUdpProtocolHeader * header = (SecUdpProtocolHeader *) headerData;
    SecUdpPeer * currentPeer;
    int sentLength;
    size_t shouldCompress = 0;
 
    host -> continueSending = 1;

    while (host -> continueSending)
    for (host -> continueSending = 0,
           currentPeer = host -> peers;
         currentPeer < & host -> peers [host -> peerCount];
         ++ currentPeer)
    {
        if (currentPeer -> state == SECUDP_PEER_STATE_DISCONNECTED ||
            currentPeer -> state == SECUDP_PEER_STATE_ZOMBIE)
          continue;

        host -> headerFlags = 0;
        host -> commandCount = 0;
        host -> bufferCount = 1;
        host -> packetSize = sizeof (SecUdpProtocolHeader);

        if (! secudp_list_empty (& currentPeer -> acknowledgements))
          secudp_protocol_send_acknowledgements (host, currentPeer);

        if (checkForTimeouts != 0 &&
            ! secudp_list_empty (& currentPeer -> sentReliableCommands) &&
            SECUDP_TIME_GREATER_EQUAL (host -> serviceTime, currentPeer -> nextTimeout) &&
            secudp_protocol_check_timeouts (host, currentPeer, event) == 1)
        {
            if (event != NULL && event -> type != SECUDP_EVENT_TYPE_NONE)
              return 1;
            else
              continue;
        }

        if ((secudp_list_empty (& currentPeer -> outgoingCommands) ||
              secudp_protocol_check_outgoing_commands (host, currentPeer)) &&
            secudp_list_empty (& currentPeer -> sentReliableCommands) &&
            SECUDP_TIME_DIFFERENCE (host -> serviceTime, currentPeer -> lastReceiveTime) >= currentPeer -> pingInterval &&
            currentPeer -> mtu - host -> packetSize >= sizeof (SecUdpProtocolPing))
        { 
            secudp_peer_ping (currentPeer);
            secudp_protocol_check_outgoing_commands (host, currentPeer);
        }

        if (host -> commandCount == 0)
          continue;

        if (currentPeer -> packetLossEpoch == 0)
          currentPeer -> packetLossEpoch = host -> serviceTime;
        else
        if (SECUDP_TIME_DIFFERENCE (host -> serviceTime, currentPeer -> packetLossEpoch) >= SECUDP_PEER_PACKET_LOSS_INTERVAL &&
            currentPeer -> packetsSent > 0)
        {
           secudp_uint32 packetLoss = currentPeer -> packetsLost * SECUDP_PEER_PACKET_LOSS_SCALE / currentPeer -> packetsSent;

#ifdef SECUDP_DEBUG
           printf ("peer %u: %f%%+-%f%% packet loss, %u+-%u ms round trip time, %f%% throttle, %u outgoing, %u/%u incoming\n", currentPeer -> incomingPeerID, currentPeer -> packetLoss / (float) SECUDP_PEER_PACKET_LOSS_SCALE, currentPeer -> packetLossVariance / (float) SECUDP_PEER_PACKET_LOSS_SCALE, currentPeer -> roundTripTime, currentPeer -> roundTripTimeVariance, currentPeer -> packetThrottle / (float) SECUDP_PEER_PACKET_THROTTLE_SCALE, secudp_list_size (& currentPeer -> outgoingCommands), currentPeer -> channels != NULL ? secudp_list_size (& currentPeer -> channels -> incomingReliableCommands) : 0, currentPeer -> channels != NULL ? secudp_list_size (& currentPeer -> channels -> incomingUnreliableCommands) : 0);
#endif

           currentPeer -> packetLossVariance = (currentPeer -> packetLossVariance * 3 + SECUDP_DIFFERENCE (packetLoss, currentPeer -> packetLoss)) / 4;
           currentPeer -> packetLoss = (currentPeer -> packetLoss * 7 + packetLoss) / 8;

           currentPeer -> packetLossEpoch = host -> serviceTime;
           currentPeer -> packetsSent = 0;
           currentPeer -> packetsLost = 0;
        }

        host -> buffers -> data = headerData;
        if (host -> headerFlags & SECUDP_PROTOCOL_HEADER_FLAG_SENT_TIME)
        {
            header -> sentTime = SECUDP_HOST_TO_NET_16 (host -> serviceTime & 0xFFFF);

            host -> buffers -> dataLength = sizeof (SecUdpProtocolHeader);
        }
        else
          host -> buffers -> dataLength = (size_t) & ((SecUdpProtocolHeader *) 0) -> sentTime;

        shouldCompress = 0;
        if (host -> compressor.context != NULL && host -> compressor.compress != NULL)
        {
            size_t originalSize = host -> packetSize - sizeof(SecUdpProtocolHeader),
                   compressedSize = host -> compressor.compress (host -> compressor.context,
                                        & host -> buffers [1], host -> bufferCount - 1,
                                        originalSize,
                                        host -> packetData [1],
                                        originalSize);
            if (compressedSize > 0 && compressedSize < originalSize)
            {
                host -> headerFlags |= SECUDP_PROTOCOL_HEADER_FLAG_COMPRESSED;
                shouldCompress = compressedSize;
#ifdef SECUDP_DEBUG_COMPRESS
                printf ("peer %u: compressed %u -> %u (%u%%)\n", currentPeer -> incomingPeerID, originalSize, compressedSize, (compressedSize * 100) / originalSize);
#endif
            }
        }

        if (currentPeer -> outgoingPeerID < SECUDP_PROTOCOL_MAXIMUM_PEER_ID)
          host -> headerFlags |= currentPeer -> outgoingSessionID << SECUDP_PROTOCOL_HEADER_SESSION_SHIFT;
        header -> peerID = SECUDP_HOST_TO_NET_16 (currentPeer -> outgoingPeerID | host -> headerFlags);
        if (host -> checksum != NULL)
        {
            secudp_uint32 * checksum = (secudp_uint32 *) & headerData [host -> buffers -> dataLength];
            * checksum = currentPeer -> outgoingPeerID < SECUDP_PROTOCOL_MAXIMUM_PEER_ID ? currentPeer -> connectID : 0;
            host -> buffers -> dataLength += sizeof (secudp_uint32);
            * checksum = host -> checksum (host -> buffers, host -> bufferCount);
        }

        if (shouldCompress > 0)
        {
            host -> buffers [1].data = host -> packetData [1];
            host -> buffers [1].dataLength = shouldCompress;
            host -> bufferCount = 2;
        }

        currentPeer -> lastSendTime = host -> serviceTime;

        sentLength = secudp_socket_send (host -> socket, & currentPeer -> address, host -> buffers, host -> bufferCount);

        secudp_protocol_remove_sent_unreliable_commands (currentPeer);

        if (sentLength < 0)
          return -1;

        host -> totalSentData += sentLength;
        host -> totalSentPackets ++;
    }
   
    return 0;
}

/** Sends any queued packets on the host specified to its designated peers.

    @param host   host to flush
    @remarks this function need only be used in circumstances where one wishes to send queued packets earlier than in a call to secudp_host_service().
    @ingroup host
*/
void
secudp_host_flush (SecUdpHost * host)
{
    host -> serviceTime = secudp_time_get ();

    secudp_protocol_send_outgoing_commands (host, NULL, 0);
}

/** Checks for any queued events on the host and dispatches one if available.

    @param host    host to check for events
    @param event   an event structure where event details will be placed if available
    @retval > 0 if an event was dispatched
    @retval 0 if no events are available
    @retval < 0 on failure
    @ingroup host
*/
int
secudp_host_check_events (SecUdpHost * host, SecUdpEvent * event)
{
    if (event == NULL) return -1;

    event -> type = SECUDP_EVENT_TYPE_NONE;
    event -> peer = NULL;
    event -> packet = NULL;

    return secudp_protocol_dispatch_incoming_commands (host, event);
}

/** Waits for events on the host specified and shuttles packets between
    the host and its peers.

    @param host    host to service
    @param event   an event structure where event details will be placed if one occurs
                   if event == NULL then no events will be delivered
    @param timeout number of milliseconds that SecUdp should wait for events
    @retval > 0 if an event occurred within the specified time limit
    @retval 0 if no event occurred
    @retval < 0 on failure
    @remarks secudp_host_service should be called fairly regularly for adequate performance
    @ingroup host
*/
int
secudp_host_service (SecUdpHost * host, SecUdpEvent * event, secudp_uint32 timeout)
{
    secudp_uint32 waitCondition;

    if (event != NULL)
    {
        event -> type = SECUDP_EVENT_TYPE_NONE;
        event -> peer = NULL;
        event -> packet = NULL;

        switch (secudp_protocol_dispatch_incoming_commands (host, event))
        {
        case 1:
            return 1;

        case -1:
#ifdef SECUDP_DEBUG
            perror ("Error dispatching incoming packets");
#endif

            return -1;

        default:
            break;
        }
    }

    host -> serviceTime = secudp_time_get ();
    
    timeout += host -> serviceTime;

    do
    {
       if (SECUDP_TIME_DIFFERENCE (host -> serviceTime, host -> bandwidthThrottleEpoch) >= SECUDP_HOST_BANDWIDTH_THROTTLE_INTERVAL)
         secudp_host_bandwidth_throttle (host);

       switch (secudp_protocol_send_outgoing_commands (host, event, 1))
       {
       case 1:
          return 1;

       case -1:
#ifdef SECUDP_DEBUG
          perror ("Error sending outgoing packets");
#endif

          return -1;

       default:
          break;
       }

       switch (secudp_protocol_receive_incoming_commands (host, event))
       {
       case 1:
          return 1;

       case -1:
#ifdef SECUDP_DEBUG
          perror ("Error receiving incoming packets");
#endif

          return -1;

       default:
          break;
       }

       switch (secudp_protocol_send_outgoing_commands (host, event, 1))
       {
       case 1:
          return 1;

       case -1:
#ifdef SECUDP_DEBUG
          perror ("Error sending outgoing packets");
#endif

          return -1;

       default:
          break;
       }

       if (event != NULL)
       {
          switch (secudp_protocol_dispatch_incoming_commands (host, event))
          {
          case 1:
             return 1;

          case -1:
#ifdef SECUDP_DEBUG
             perror ("Error dispatching incoming packets");
#endif

             return -1;

          default:
             break;
          }
       }

       if (SECUDP_TIME_GREATER_EQUAL (host -> serviceTime, timeout))
         return 0;

       do
       {
          host -> serviceTime = secudp_time_get ();

          if (SECUDP_TIME_GREATER_EQUAL (host -> serviceTime, timeout))
            return 0;

          waitCondition = SECUDP_SOCKET_WAIT_RECEIVE | SECUDP_SOCKET_WAIT_INTERRUPT;

          if (secudp_socket_wait (host -> socket, & waitCondition, SECUDP_TIME_DIFFERENCE (timeout, host -> serviceTime)) != 0)
            return -1;
       }
       while (waitCondition & SECUDP_SOCKET_WAIT_INTERRUPT);

       host -> serviceTime = secudp_time_get ();
    } while (waitCondition & SECUDP_SOCKET_WAIT_RECEIVE);

    return 0; 
}

