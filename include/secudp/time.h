/** 
 @file  time.h
 @brief SecUdp time constants and macros
*/
#ifndef __SECUDP_TIME_H__
#define __SECUDP_TIME_H__

#define SECUDP_TIME_OVERFLOW 86400000

#define SECUDP_TIME_LESS(a, b) ((a) - (b) >= SECUDP_TIME_OVERFLOW)
#define SECUDP_TIME_GREATER(a, b) ((b) - (a) >= SECUDP_TIME_OVERFLOW)
#define SECUDP_TIME_LESS_EQUAL(a, b) (! SECUDP_TIME_GREATER (a, b))
#define SECUDP_TIME_GREATER_EQUAL(a, b) (! SECUDP_TIME_LESS (a, b))

#define SECUDP_TIME_DIFFERENCE(a, b) ((a) - (b) >= SECUDP_TIME_OVERFLOW ? (b) - (a) : (a) - (b))

#endif /* __SECUDP_TIME_H__ */

