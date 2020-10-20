/** 
 @file  list.h
 @brief SecUdp list management 
*/
#ifndef __SECUDP_LIST_H__
#define __SECUDP_LIST_H__

#include <stdlib.h>

typedef struct _SecUdpListNode
{
   struct _SecUdpListNode * next;
   struct _SecUdpListNode * previous;
} SecUdpListNode;

typedef SecUdpListNode * SecUdpListIterator;

typedef struct _SecUdpList
{
   SecUdpListNode sentinel;
} SecUdpList;

extern void secudp_list_clear (SecUdpList *);

extern SecUdpListIterator secudp_list_insert (SecUdpListIterator, void *);
extern void * secudp_list_remove (SecUdpListIterator);
extern SecUdpListIterator secudp_list_move (SecUdpListIterator, void *, void *);

extern size_t secudp_list_size (SecUdpList *);

#define secudp_list_begin(list) ((list) -> sentinel.next)
#define secudp_list_end(list) (& (list) -> sentinel)

#define secudp_list_empty(list) (secudp_list_begin (list) == secudp_list_end (list))

#define secudp_list_next(iterator) ((iterator) -> next)
#define secudp_list_previous(iterator) ((iterator) -> previous)

#define secudp_list_front(list) ((void *) (list) -> sentinel.next)
#define secudp_list_back(list) ((void *) (list) -> sentinel.previous)

#endif /* __SECUDP_LIST_H__ */

