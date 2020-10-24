/** 
 @file callbacks.c
 @brief SecUdp callback functions
*/
#define SECUDP_BUILDING_LIB 1
#include "secudp/secudp.h"

static SecUdpCallbacks callbacks = { malloc, free, abort };

int
secudp_initialize_with_callbacks (SecUdpVersion version, const SecUdpCallbacks * inits)
{
   if (version < SECUDP_VERSION_CREATE (1, 0, 0))
     return -1;

   if (inits -> malloc != NULL || inits -> free != NULL)
   {
      if (inits -> malloc == NULL || inits -> free == NULL)
        return -1;

      callbacks.malloc = inits -> malloc;
      callbacks.free = inits -> free;
   }
      
   if (inits -> no_memory != NULL)
     callbacks.no_memory = inits -> no_memory;

   return secudp_initialize ();
}

SecUdpVersion
secudp_linked_version (void)
{
    return SECUDP_VERSION;
}
           
void *
secudp_malloc (size_t size)
{
   void * memory = callbacks.malloc (size);

   if (memory == NULL)
     callbacks.no_memory ();

   return memory;
}

void
secudp_free (void * memory)
{
   callbacks.free (memory);
}

