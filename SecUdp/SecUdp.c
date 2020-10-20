#include "SecUdp.h"

SecUdpHost *secudp_host_create(
  const SecUdpAddress *address, const SecUdpHostSecret *secret,
  size_t peerCount, size_t channelLimit, 
  enet_uint32 incomingBandwidth, enet_uint32 outgoingBandwidth) {

  ENetHost *host = enet_host_create((ENetAddress *)address, peerCount, 
                                    channelLimit, incomingBandwidth, 
                                    outgoingBandwidth);

  if(host) {
    SecUdpHost *newHost = enet_malloc(sizeof(SecUdpHost));
    if(newHost) {
      newHost->secret = enet_malloc(sizeof(SecUdpHostSecret));
      if(newHost->secret) {
        *newHost->secret = *secret;
        *(ENetHost *)newHost = *host;
      } else {
        enet_free(newHost);
        newHost = 0;	
      }
    }
    enet_free(host);
    host = (ENetHost *)newHost;
  }

  return (SecUdpHost *)host;
}

void secudp_host_destroy(SecUdpHost *host) {
  size_t i;

  enet_free(host->secret);
  for(i = 0; i < host->peerCount; i++) {
    enet_free(host->peers[i].data);
  }
  enet_host_destroy((ENetHost *)host);
}

SecUdpPeer *secudp_host_connect(SecUdpHost *host, const SecUdpAddress *address, 
                                size_t channelCount, enet_uint32 data) {
  ENetHost *ehost = (ENetHost *)host;
  ENetAddress *eaddr = (ENetAddress *)address;
  ENetPeer *peer = enet_host_connect(ehost, eaddr, channelCount, data);
  peer->data = enet_malloc(sizeof(SecUdpData));
  if(peer->data) {
    ((SecUdpData *)peer->data)->counter = 0;
    ((SecUdpData *)peer->data)->data = 0;
  } else {
    enet_peer_disconnect(peer, 0);
    peer = 0;
  }
  return (SecUdpPeer *)peer;
}

int secudp_initialize() {
  int status = enet_initialize();

  return status;
}

int secudp_host_service(SecUdpHost *host, SecUdpEvent *event, enet_uint32 timeout) {
  ENetHost *ehost = (ENetHost *)host;
  ENetEvent *eevent = (ENetEvent *)event;
  SecUdpPacket *packet;
  int status = enet_host_service(ehost, eevent, timeout);

  if(status > 0) {
    switch(event->type) {
      case ENET_EVENT_TYPE_CONNECT: {
        event->type = SECUDP_EVENT_TYPE_HANDSHAKING;
	break;
      }
    } 
  }
  return status;
}

int main() {
  return 0;
}
