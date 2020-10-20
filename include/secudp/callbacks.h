/** 
 @file  callbacks.h
 @brief SecUdp callbacks
*/
#ifndef __SECUDP_CALLBACKS_H__
#define __SECUDP_CALLBACKS_H__

#include <stdlib.h>

typedef struct _SecUdpCallbacks
{
    void * (SECUDP_CALLBACK * malloc) (size_t size);
    void (SECUDP_CALLBACK * free) (void * memory);
    void (SECUDP_CALLBACK * no_memory) (void);
} SecUdpCallbacks;

/** @defgroup callbacks SecUdp internal callbacks
    @{
    @ingroup private
*/
extern void * secudp_malloc (size_t);
extern void   secudp_free (void *);

/** @} */

#endif /* __SECUDP_CALLBACKS_H__ */

