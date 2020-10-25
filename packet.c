/** 
 @file  packet.c
 @brief SecUdp packet management functions
*/
#include <string.h>
#define SECUDP_BUILDING_LIB 1
#include "secudp/secudp.h"
#include "secudp/crypto.h"

/** @defgroup Packet SecUdp packet functions 
    @{ 
*/

/** Creates a packet that may be sent to a peer.
    @param data         initial contents of the packet's data; the packet's data will remain uninitialized if data is NULL.
    @param dataLength   size of the data allocated for this packet
    @param flags        flags for this packet as described for the SecUdpPacket structure.
    @returns the packet on success, NULL on failure
*/
SecUdpPacket *
secudp_packet_create (const void * data, size_t dataLength, secudp_uint32 flags)
{
    SecUdpPacket * packet;
    
    packet = (SecUdpPacket *) secudp_malloc (sizeof (SecUdpPacket));
    if (packet == NULL)
      return NULL;

    if (flags & SECUDP_PACKET_FLAG_NO_ALLOCATE)
      packet -> data = (secudp_uint8 *) data;
    else
    if (dataLength <= 0)
      packet -> data = NULL;
    else
    {
       packet -> data = (secudp_uint8 *) secudp_malloc (dataLength);
       if (packet -> data == NULL)
       {
          secudp_free (packet);
          return NULL;
       }

       if (data != NULL)
         memcpy (packet -> data, data, dataLength);
    }

    packet -> referenceCount = 0;
    packet -> flags = flags;
    packet -> dataLength = dataLength;
    packet -> ciphertext = NULL;
    packet -> freeCallback = NULL;
    packet -> userData = NULL;

    return packet;
}

/** Destroys the packet and deallocates its data.
    @param packet packet to be destroyed
*/
void
secudp_packet_destroy (SecUdpPacket * packet)
{
    if (packet == NULL)
      return;

    if (packet -> freeCallback != NULL)
      (* packet -> freeCallback) (packet);
    if (! (packet -> flags & SECUDP_PACKET_FLAG_NO_ALLOCATE) &&
        packet -> data != NULL)
      secudp_free (packet -> data);
    if(packet -> ciphertext != NULL)
      secudp_free(packet -> ciphertext);
    secudp_free (packet);
}

/** Attempts to resize the data in the packet to length specified in the 
    dataLength parameter 
    @param packet packet to resize
    @param dataLength new size for the packet data
    @returns 0 on success, < 0 on failure
*/
int
secudp_packet_resize (SecUdpPacket * packet, size_t dataLength)
{
    secudp_uint8 * newData;
   
    if (dataLength <= packet -> dataLength || (packet -> flags & SECUDP_PACKET_FLAG_NO_ALLOCATE))
    {
       packet -> dataLength = dataLength;

       return 0;
    }

    newData = (secudp_uint8 *) secudp_malloc (dataLength);
    if (newData == NULL)
      return -1;

    memcpy (newData, packet -> data, packet -> dataLength);
    secudp_free (packet -> data);
    
    packet -> data = newData;
    packet -> dataLength = dataLength;

    return 0;
}

static int initializedCRC32 = 0;
static secudp_uint32 crcTable [256];

static secudp_uint32 
reflect_crc (int val, int bits)
{
    int result = 0, bit;

    for (bit = 0; bit < bits; bit ++)
    {
        if(val & 1) result |= 1 << (bits - 1 - bit); 
        val >>= 1;
    }

    return result;
}

static void 
initialize_crc32 (void)
{
    int byte;

    for (byte = 0; byte < 256; ++ byte)
    {
        secudp_uint32 crc = reflect_crc (byte, 8) << 24;
        int offset;

        for(offset = 0; offset < 8; ++ offset)
        {
            if (crc & 0x80000000)
                crc = (crc << 1) ^ 0x04c11db7;
            else
                crc <<= 1;
        }

        crcTable [byte] = reflect_crc (crc, 32);
    }

    initializedCRC32 = 1;
}
    
secudp_uint32
secudp_crc32 (const SecUdpBuffer * buffers, size_t bufferCount)
{
    secudp_uint32 crc = 0xFFFFFFFF;
    
    if (! initializedCRC32) initialize_crc32 ();

    while (bufferCount -- > 0)
    {
        const secudp_uint8 * data = (const secudp_uint8 *) buffers -> data,
                         * dataEnd = & data [buffers -> dataLength];

        while (data < dataEnd)
        {
            crc = (crc >> 8) ^ crcTable [(crc & 0xFF) ^ *data++];        
        }

        ++ buffers;
    }

    return SECUDP_HOST_TO_NET_32 (~ crc);
}

/** @} */
