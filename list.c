/** 
 @file list.c
 @brief SecUdp linked list functions
*/
#define SECUDP_BUILDING_LIB 1
#include "SecUdp/SecUdp.h"

/** 
    @defgroup list SecUdp linked list utility functions
    @ingroup private
    @{
*/
void
secudp_list_clear (SecUdpList * list)
{
   list -> sentinel.next = & list -> sentinel;
   list -> sentinel.previous = & list -> sentinel;
}

SecUdpListIterator
secudp_list_insert (SecUdpListIterator position, void * data)
{
   SecUdpListIterator result = (SecUdpListIterator) data;

   result -> previous = position -> previous;
   result -> next = position;

   result -> previous -> next = result;
   position -> previous = result;

   return result;
}

void *
secudp_list_remove (SecUdpListIterator position)
{
   position -> previous -> next = position -> next;
   position -> next -> previous = position -> previous;

   return position;
}

SecUdpListIterator
secudp_list_move (SecUdpListIterator position, void * dataFirst, void * dataLast)
{
   SecUdpListIterator first = (SecUdpListIterator) dataFirst,
                    last = (SecUdpListIterator) dataLast;

   first -> previous -> next = last -> next;
   last -> next -> previous = first -> previous;

   first -> previous = position -> previous;
   last -> next = position;

   first -> previous -> next = first;
   position -> previous = last;
    
   return first;
}

size_t
secudp_list_size (SecUdpList * list)
{
   size_t size = 0;
   SecUdpListIterator position;

   for (position = secudp_list_begin (list);
        position != secudp_list_end (list);
        position = secudp_list_next (position))
     ++ size;
   
   return size;
}

/** @} */
