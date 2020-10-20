/** 
 @file compress.c
 @brief An adaptive order-2 PPM range coder
*/
#define SECUDP_BUILDING_LIB 1
#include <string.h>
#include "secudp/secudp.h"

typedef struct _SecUdpSymbol
{
    /* binary indexed tree of symbols */
    secudp_uint8 value;
    secudp_uint8 count;
    secudp_uint16 under;
    secudp_uint16 left, right;

    /* context defined by this symbol */
    secudp_uint16 symbols;
    secudp_uint16 escapes;
    secudp_uint16 total;
    secudp_uint16 parent; 
} SecUdpSymbol;

/* adaptation constants tuned aggressively for small packet sizes rather than large file compression */
enum
{
    SECUDP_RANGE_CODER_TOP    = 1<<24,
    SECUDP_RANGE_CODER_BOTTOM = 1<<16,

    SECUDP_CONTEXT_SYMBOL_DELTA = 3,
    SECUDP_CONTEXT_SYMBOL_MINIMUM = 1,
    SECUDP_CONTEXT_ESCAPE_MINIMUM = 1,

    SECUDP_SUBCONTEXT_ORDER = 2,
    SECUDP_SUBCONTEXT_SYMBOL_DELTA = 2,
    SECUDP_SUBCONTEXT_ESCAPE_DELTA = 5
};

/* context exclusion roughly halves compression speed, so disable for now */
#undef SECUDP_CONTEXT_EXCLUSION

typedef struct _SecUdpRangeCoder
{
    /* only allocate enough symbols for reasonable MTUs, would need to be larger for large file compression */
    SecUdpSymbol symbols[4096];
} SecUdpRangeCoder;

void *
secudp_range_coder_create (void)
{
    SecUdpRangeCoder * rangeCoder = (SecUdpRangeCoder *) secudp_malloc (sizeof (SecUdpRangeCoder));
    if (rangeCoder == NULL)
      return NULL;

    return rangeCoder;
}

void
secudp_range_coder_destroy (void * context)
{
    SecUdpRangeCoder * rangeCoder = (SecUdpRangeCoder *) context;
    if (rangeCoder == NULL)
      return;

    secudp_free (rangeCoder);
}

#define SECUDP_SYMBOL_CREATE(symbol, value_, count_) \
{ \
    symbol = & rangeCoder -> symbols [nextSymbol ++]; \
    symbol -> value = value_; \
    symbol -> count = count_; \
    symbol -> under = count_; \
    symbol -> left = 0; \
    symbol -> right = 0; \
    symbol -> symbols = 0; \
    symbol -> escapes = 0; \
    symbol -> total = 0; \
    symbol -> parent = 0; \
}

#define SECUDP_CONTEXT_CREATE(context, escapes_, minimum) \
{ \
    SECUDP_SYMBOL_CREATE (context, 0, 0); \
    (context) -> escapes = escapes_; \
    (context) -> total = escapes_ + 256*minimum; \
    (context) -> symbols = 0; \
}

static secudp_uint16
secudp_symbol_rescale (SecUdpSymbol * symbol)
{
    secudp_uint16 total = 0;
    for (;;)
    {
        symbol -> count -= symbol->count >> 1;
        symbol -> under = symbol -> count;
        if (symbol -> left)
          symbol -> under += secudp_symbol_rescale (symbol + symbol -> left);
        total += symbol -> under;
        if (! symbol -> right) break;
        symbol += symbol -> right;
    } 
    return total;
}

#define SECUDP_CONTEXT_RESCALE(context, minimum) \
{ \
    (context) -> total = (context) -> symbols ? secudp_symbol_rescale ((context) + (context) -> symbols) : 0; \
    (context) -> escapes -= (context) -> escapes >> 1; \
    (context) -> total += (context) -> escapes + 256*minimum; \
}

#define SECUDP_RANGE_CODER_OUTPUT(value) \
{ \
    if (outData >= outEnd) \
      return 0; \
    * outData ++ = value; \
}

#define SECUDP_RANGE_CODER_ENCODE(under, count, total) \
{ \
    encodeRange /= (total); \
    encodeLow += (under) * encodeRange; \
    encodeRange *= (count); \
    for (;;) \
    { \
        if((encodeLow ^ (encodeLow + encodeRange)) >= SECUDP_RANGE_CODER_TOP) \
        { \
            if(encodeRange >= SECUDP_RANGE_CODER_BOTTOM) break; \
            encodeRange = -encodeLow & (SECUDP_RANGE_CODER_BOTTOM - 1); \
        } \
        SECUDP_RANGE_CODER_OUTPUT (encodeLow >> 24); \
        encodeRange <<= 8; \
        encodeLow <<= 8; \
    } \
}

#define SECUDP_RANGE_CODER_FLUSH \
{ \
    while (encodeLow) \
    { \
        SECUDP_RANGE_CODER_OUTPUT (encodeLow >> 24); \
        encodeLow <<= 8; \
    } \
}

#define SECUDP_RANGE_CODER_FREE_SYMBOLS \
{ \
    if (nextSymbol >= sizeof (rangeCoder -> symbols) / sizeof (SecUdpSymbol) - SECUDP_SUBCONTEXT_ORDER ) \
    { \
        nextSymbol = 0; \
        SECUDP_CONTEXT_CREATE (root, SECUDP_CONTEXT_ESCAPE_MINIMUM, SECUDP_CONTEXT_SYMBOL_MINIMUM); \
        predicted = 0; \
        order = 0; \
    } \
}

#define SECUDP_CONTEXT_ENCODE(context, symbol_, value_, under_, count_, update, minimum) \
{ \
    under_ = value*minimum; \
    count_ = minimum; \
    if (! (context) -> symbols) \
    { \
        SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
        (context) -> symbols = symbol_ - (context); \
    } \
    else \
    { \
        SecUdpSymbol * node = (context) + (context) -> symbols; \
        for (;;) \
        { \
            if (value_ < node -> value) \
            { \
                node -> under += update; \
                if (node -> left) { node += node -> left; continue; } \
                SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
                node -> left = symbol_ - node; \
            } \
            else \
            if (value_ > node -> value) \
            { \
                under_ += node -> under; \
                if (node -> right) { node += node -> right; continue; } \
                SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
                node -> right = symbol_ - node; \
            } \
            else \
            { \
                count_ += node -> count; \
                under_ += node -> under - node -> count; \
                node -> under += update; \
                node -> count += update; \
                symbol_ = node; \
            } \
            break; \
        } \
    } \
}

#ifdef SECUDP_CONTEXT_EXCLUSION
static const SecUdpSymbol emptyContext = { 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#define SECUDP_CONTEXT_WALK(context, body) \
{ \
    const SecUdpSymbol * node = (context) + (context) -> symbols; \
    const SecUdpSymbol * stack [256]; \
    size_t stackSize = 0; \
    while (node -> left) \
    { \
        stack [stackSize ++] = node; \
        node += node -> left; \
    } \
    for (;;) \
    { \
        body; \
        if (node -> right) \
        { \
            node += node -> right; \
            while (node -> left) \
            { \
                stack [stackSize ++] = node; \
                node += node -> left; \
            } \
        } \
        else \
        if (stackSize <= 0) \
            break; \
        else \
            node = stack [-- stackSize]; \
    } \
}

#define SECUDP_CONTEXT_ENCODE_EXCLUDE(context, value_, under, total, minimum) \
SECUDP_CONTEXT_WALK(context, { \
    if (node -> value != value_) \
    { \
        secudp_uint16 parentCount = rangeCoder -> symbols [node -> parent].count + minimum; \
        if (node -> value < value_) \
          under -= parentCount; \
        total -= parentCount; \
    } \
})
#endif

size_t
secudp_range_coder_compress (void * context, const SecUdpBuffer * inBuffers, size_t inBufferCount, size_t inLimit, secudp_uint8 * outData, size_t outLimit)
{
    SecUdpRangeCoder * rangeCoder = (SecUdpRangeCoder *) context;
    secudp_uint8 * outStart = outData, * outEnd = & outData [outLimit];
    const secudp_uint8 * inData, * inEnd;
    secudp_uint32 encodeLow = 0, encodeRange = ~0;
    SecUdpSymbol * root;
    secudp_uint16 predicted = 0;
    size_t order = 0, nextSymbol = 0;

    if (rangeCoder == NULL || inBufferCount <= 0 || inLimit <= 0)
      return 0;

    inData = (const secudp_uint8 *) inBuffers -> data;
    inEnd = & inData [inBuffers -> dataLength];
    inBuffers ++;
    inBufferCount --;

    SECUDP_CONTEXT_CREATE (root, SECUDP_CONTEXT_ESCAPE_MINIMUM, SECUDP_CONTEXT_SYMBOL_MINIMUM);

    for (;;)
    {
        SecUdpSymbol * subcontext, * symbol;
#ifdef SECUDP_CONTEXT_EXCLUSION
        const SecUdpSymbol * childContext = & emptyContext;
#endif
        secudp_uint8 value;
        secudp_uint16 count, under, * parent = & predicted, total;
        if (inData >= inEnd)
        {
            if (inBufferCount <= 0)
              break;
            inData = (const secudp_uint8 *) inBuffers -> data;
            inEnd = & inData [inBuffers -> dataLength];
            inBuffers ++;
            inBufferCount --;
        }
        value = * inData ++;
    
        for (subcontext = & rangeCoder -> symbols [predicted]; 
             subcontext != root; 
#ifdef SECUDP_CONTEXT_EXCLUSION
             childContext = subcontext, 
#endif
                subcontext = & rangeCoder -> symbols [subcontext -> parent])
        {
            SECUDP_CONTEXT_ENCODE (subcontext, symbol, value, under, count, SECUDP_SUBCONTEXT_SYMBOL_DELTA, 0);
            * parent = symbol - rangeCoder -> symbols;
            parent = & symbol -> parent;
            total = subcontext -> total;
#ifdef SECUDP_CONTEXT_EXCLUSION
            if (childContext -> total > SECUDP_SUBCONTEXT_SYMBOL_DELTA + SECUDP_SUBCONTEXT_ESCAPE_DELTA)
              SECUDP_CONTEXT_ENCODE_EXCLUDE (childContext, value, under, total, 0);
#endif
            if (count > 0)
            {
                SECUDP_RANGE_CODER_ENCODE (subcontext -> escapes + under, count, total);
            }
            else
            {
                if (subcontext -> escapes > 0 && subcontext -> escapes < total) 
                    SECUDP_RANGE_CODER_ENCODE (0, subcontext -> escapes, total); 
                subcontext -> escapes += SECUDP_SUBCONTEXT_ESCAPE_DELTA;
                subcontext -> total += SECUDP_SUBCONTEXT_ESCAPE_DELTA;
            }
            subcontext -> total += SECUDP_SUBCONTEXT_SYMBOL_DELTA;
            if (count > 0xFF - 2*SECUDP_SUBCONTEXT_SYMBOL_DELTA || subcontext -> total > SECUDP_RANGE_CODER_BOTTOM - 0x100)
              SECUDP_CONTEXT_RESCALE (subcontext, 0);
            if (count > 0) goto nextInput;
        }

        SECUDP_CONTEXT_ENCODE (root, symbol, value, under, count, SECUDP_CONTEXT_SYMBOL_DELTA, SECUDP_CONTEXT_SYMBOL_MINIMUM);
        * parent = symbol - rangeCoder -> symbols;
        parent = & symbol -> parent;
        total = root -> total;
#ifdef SECUDP_CONTEXT_EXCLUSION
        if (childContext -> total > SECUDP_SUBCONTEXT_SYMBOL_DELTA + SECUDP_SUBCONTEXT_ESCAPE_DELTA)
          SECUDP_CONTEXT_ENCODE_EXCLUDE (childContext, value, under, total, SECUDP_CONTEXT_SYMBOL_MINIMUM); 
#endif
        SECUDP_RANGE_CODER_ENCODE (root -> escapes + under, count, total);
        root -> total += SECUDP_CONTEXT_SYMBOL_DELTA; 
        if (count > 0xFF - 2*SECUDP_CONTEXT_SYMBOL_DELTA + SECUDP_CONTEXT_SYMBOL_MINIMUM || root -> total > SECUDP_RANGE_CODER_BOTTOM - 0x100)
          SECUDP_CONTEXT_RESCALE (root, SECUDP_CONTEXT_SYMBOL_MINIMUM);

    nextInput:
        if (order >= SECUDP_SUBCONTEXT_ORDER) 
          predicted = rangeCoder -> symbols [predicted].parent;
        else 
          order ++;
        SECUDP_RANGE_CODER_FREE_SYMBOLS;
    }

    SECUDP_RANGE_CODER_FLUSH;

    return (size_t) (outData - outStart);
}

#define SECUDP_RANGE_CODER_SEED \
{ \
    if (inData < inEnd) decodeCode |= * inData ++ << 24; \
    if (inData < inEnd) decodeCode |= * inData ++ << 16; \
    if (inData < inEnd) decodeCode |= * inData ++ << 8; \
    if (inData < inEnd) decodeCode |= * inData ++; \
}

#define SECUDP_RANGE_CODER_READ(total) ((decodeCode - decodeLow) / (decodeRange /= (total)))

#define SECUDP_RANGE_CODER_DECODE(under, count, total) \
{ \
    decodeLow += (under) * decodeRange; \
    decodeRange *= (count); \
    for (;;) \
    { \
        if((decodeLow ^ (decodeLow + decodeRange)) >= SECUDP_RANGE_CODER_TOP) \
        { \
            if(decodeRange >= SECUDP_RANGE_CODER_BOTTOM) break; \
            decodeRange = -decodeLow & (SECUDP_RANGE_CODER_BOTTOM - 1); \
        } \
        decodeCode <<= 8; \
        if (inData < inEnd) \
          decodeCode |= * inData ++; \
        decodeRange <<= 8; \
        decodeLow <<= 8; \
    } \
}

#define SECUDP_CONTEXT_DECODE(context, symbol_, code, value_, under_, count_, update, minimum, createRoot, visitNode, createRight, createLeft) \
{ \
    under_ = 0; \
    count_ = minimum; \
    if (! (context) -> symbols) \
    { \
        createRoot; \
    } \
    else \
    { \
        SecUdpSymbol * node = (context) + (context) -> symbols; \
        for (;;) \
        { \
            secudp_uint16 after = under_ + node -> under + (node -> value + 1)*minimum, before = node -> count + minimum; \
            visitNode; \
            if (code >= after) \
            { \
                under_ += node -> under; \
                if (node -> right) { node += node -> right; continue; } \
                createRight; \
            } \
            else \
            if (code < after - before) \
            { \
                node -> under += update; \
                if (node -> left) { node += node -> left; continue; } \
                createLeft; \
            } \
            else \
            { \
                value_ = node -> value; \
                count_ += node -> count; \
                under_ = after - before; \
                node -> under += update; \
                node -> count += update; \
                symbol_ = node; \
            } \
            break; \
        } \
    } \
}

#define SECUDP_CONTEXT_TRY_DECODE(context, symbol_, code, value_, under_, count_, update, minimum, exclude) \
SECUDP_CONTEXT_DECODE (context, symbol_, code, value_, under_, count_, update, minimum, return 0, exclude (node -> value, after, before), return 0, return 0)

#define SECUDP_CONTEXT_ROOT_DECODE(context, symbol_, code, value_, under_, count_, update, minimum, exclude) \
SECUDP_CONTEXT_DECODE (context, symbol_, code, value_, under_, count_, update, minimum, \
    { \
        value_ = code / minimum; \
        under_ = code - code%minimum; \
        SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
        (context) -> symbols = symbol_ - (context); \
    }, \
    exclude (node -> value, after, before), \
    { \
        value_ = node->value + 1 + (code - after)/minimum; \
        under_ = code - (code - after)%minimum; \
        SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
        node -> right = symbol_ - node; \
    }, \
    { \
        value_ = node->value - 1 - (after - before - code - 1)/minimum; \
        under_ = code - (after - before - code - 1)%minimum; \
        SECUDP_SYMBOL_CREATE (symbol_, value_, update); \
        node -> left = symbol_ - node; \
    }) \

#ifdef SECUDP_CONTEXT_EXCLUSION
typedef struct _SecUdpExclude
{
    secudp_uint8 value;
    secudp_uint16 under;
} SecUdpExclude;

#define SECUDP_CONTEXT_DECODE_EXCLUDE(context, total, minimum) \
{ \
    secudp_uint16 under = 0; \
    nextExclude = excludes; \
    SECUDP_CONTEXT_WALK (context, { \
        under += rangeCoder -> symbols [node -> parent].count + minimum; \
        nextExclude -> value = node -> value; \
        nextExclude -> under = under; \
        nextExclude ++; \
    }); \
    total -= under; \
}

#define SECUDP_CONTEXT_EXCLUDED(value_, after, before) \
{ \
    size_t low = 0, high = nextExclude - excludes; \
    for(;;) \
    { \
        size_t mid = (low + high) >> 1; \
        const SecUdpExclude * exclude = & excludes [mid]; \
        if (value_ < exclude -> value) \
        { \
            if (low + 1 < high) \
            { \
                high = mid; \
                continue; \
            } \
            if (exclude > excludes) \
              after -= exclude [-1].under; \
        } \
        else \
        { \
            if (value_ > exclude -> value) \
            { \
                if (low + 1 < high) \
                { \
                    low = mid; \
                    continue; \
                } \
            } \
            else \
              before = 0; \
            after -= exclude -> under; \
        } \
        break; \
    } \
}
#endif

#define SECUDP_CONTEXT_NOT_EXCLUDED(value_, after, before)

size_t
secudp_range_coder_decompress (void * context, const secudp_uint8 * inData, size_t inLimit, secudp_uint8 * outData, size_t outLimit)
{
    SecUdpRangeCoder * rangeCoder = (SecUdpRangeCoder *) context;
    secudp_uint8 * outStart = outData, * outEnd = & outData [outLimit];
    const secudp_uint8 * inEnd = & inData [inLimit];
    secudp_uint32 decodeLow = 0, decodeCode = 0, decodeRange = ~0;
    SecUdpSymbol * root;
    secudp_uint16 predicted = 0;
    size_t order = 0, nextSymbol = 0;
#ifdef SECUDP_CONTEXT_EXCLUSION
    SecUdpExclude excludes [256];
    SecUdpExclude * nextExclude = excludes;
#endif
  
    if (rangeCoder == NULL || inLimit <= 0)
      return 0;

    SECUDP_CONTEXT_CREATE (root, SECUDP_CONTEXT_ESCAPE_MINIMUM, SECUDP_CONTEXT_SYMBOL_MINIMUM);

    SECUDP_RANGE_CODER_SEED;

    for (;;)
    {
        SecUdpSymbol * subcontext, * symbol, * patch;
#ifdef SECUDP_CONTEXT_EXCLUSION
        const SecUdpSymbol * childContext = & emptyContext;
#endif
        secudp_uint8 value = 0;
        secudp_uint16 code, under, count, bottom, * parent = & predicted, total;

        for (subcontext = & rangeCoder -> symbols [predicted];
             subcontext != root;
#ifdef SECUDP_CONTEXT_EXCLUSION
             childContext = subcontext, 
#endif
                subcontext = & rangeCoder -> symbols [subcontext -> parent])
        {
            if (subcontext -> escapes <= 0)
              continue;
            total = subcontext -> total;
#ifdef SECUDP_CONTEXT_EXCLUSION
            if (childContext -> total > 0) 
              SECUDP_CONTEXT_DECODE_EXCLUDE (childContext, total, 0); 
#endif
            if (subcontext -> escapes >= total)
              continue;
            code = SECUDP_RANGE_CODER_READ (total);
            if (code < subcontext -> escapes) 
            {
                SECUDP_RANGE_CODER_DECODE (0, subcontext -> escapes, total); 
                continue;
            }
            code -= subcontext -> escapes;
#ifdef SECUDP_CONTEXT_EXCLUSION
            if (childContext -> total > 0)
            {
                SECUDP_CONTEXT_TRY_DECODE (subcontext, symbol, code, value, under, count, SECUDP_SUBCONTEXT_SYMBOL_DELTA, 0, SECUDP_CONTEXT_EXCLUDED); 
            }
            else
#endif
            {
                SECUDP_CONTEXT_TRY_DECODE (subcontext, symbol, code, value, under, count, SECUDP_SUBCONTEXT_SYMBOL_DELTA, 0, SECUDP_CONTEXT_NOT_EXCLUDED); 
            }
            bottom = symbol - rangeCoder -> symbols;
            SECUDP_RANGE_CODER_DECODE (subcontext -> escapes + under, count, total);
            subcontext -> total += SECUDP_SUBCONTEXT_SYMBOL_DELTA;
            if (count > 0xFF - 2*SECUDP_SUBCONTEXT_SYMBOL_DELTA || subcontext -> total > SECUDP_RANGE_CODER_BOTTOM - 0x100)
              SECUDP_CONTEXT_RESCALE (subcontext, 0);
            goto patchContexts;
        }

        total = root -> total;
#ifdef SECUDP_CONTEXT_EXCLUSION
        if (childContext -> total > 0)
          SECUDP_CONTEXT_DECODE_EXCLUDE (childContext, total, SECUDP_CONTEXT_SYMBOL_MINIMUM);  
#endif
        code = SECUDP_RANGE_CODER_READ (total);
        if (code < root -> escapes)
        {
            SECUDP_RANGE_CODER_DECODE (0, root -> escapes, total);
            break;
        }
        code -= root -> escapes;
#ifdef SECUDP_CONTEXT_EXCLUSION
        if (childContext -> total > 0)
        {
            SECUDP_CONTEXT_ROOT_DECODE (root, symbol, code, value, under, count, SECUDP_CONTEXT_SYMBOL_DELTA, SECUDP_CONTEXT_SYMBOL_MINIMUM, SECUDP_CONTEXT_EXCLUDED); 
        }
        else
#endif
        {
            SECUDP_CONTEXT_ROOT_DECODE (root, symbol, code, value, under, count, SECUDP_CONTEXT_SYMBOL_DELTA, SECUDP_CONTEXT_SYMBOL_MINIMUM, SECUDP_CONTEXT_NOT_EXCLUDED); 
        }
        bottom = symbol - rangeCoder -> symbols;
        SECUDP_RANGE_CODER_DECODE (root -> escapes + under, count, total);
        root -> total += SECUDP_CONTEXT_SYMBOL_DELTA;
        if (count > 0xFF - 2*SECUDP_CONTEXT_SYMBOL_DELTA + SECUDP_CONTEXT_SYMBOL_MINIMUM || root -> total > SECUDP_RANGE_CODER_BOTTOM - 0x100)
          SECUDP_CONTEXT_RESCALE (root, SECUDP_CONTEXT_SYMBOL_MINIMUM);

    patchContexts:
        for (patch = & rangeCoder -> symbols [predicted];
             patch != subcontext;
             patch = & rangeCoder -> symbols [patch -> parent])
        {
            SECUDP_CONTEXT_ENCODE (patch, symbol, value, under, count, SECUDP_SUBCONTEXT_SYMBOL_DELTA, 0);
            * parent = symbol - rangeCoder -> symbols;
            parent = & symbol -> parent;
            if (count <= 0)
            {
                patch -> escapes += SECUDP_SUBCONTEXT_ESCAPE_DELTA;
                patch -> total += SECUDP_SUBCONTEXT_ESCAPE_DELTA;
            }
            patch -> total += SECUDP_SUBCONTEXT_SYMBOL_DELTA; 
            if (count > 0xFF - 2*SECUDP_SUBCONTEXT_SYMBOL_DELTA || patch -> total > SECUDP_RANGE_CODER_BOTTOM - 0x100)
              SECUDP_CONTEXT_RESCALE (patch, 0);
        }
        * parent = bottom;

        SECUDP_RANGE_CODER_OUTPUT (value);

        if (order >= SECUDP_SUBCONTEXT_ORDER)
          predicted = rangeCoder -> symbols [predicted].parent;
        else
          order ++;
        SECUDP_RANGE_CODER_FREE_SYMBOLS;
    }
                        
    return (size_t) (outData - outStart);
}

/** @defgroup host SecUdp host functions
    @{
*/

/** Sets the packet compressor the host should use to the default range coder.
    @param host host to enable the range coder for
    @returns 0 on success, < 0 on failure
*/
int
secudp_host_compress_with_range_coder (SecUdpHost * host)
{
    SecUdpCompressor compressor;
    memset (& compressor, 0, sizeof (compressor));
    compressor.context = secudp_range_coder_create();
    if (compressor.context == NULL)
      return -1;
    compressor.compress = secudp_range_coder_compress;
    compressor.decompress = secudp_range_coder_decompress;
    compressor.destroy = secudp_range_coder_destroy;
    secudp_host_compress (host, & compressor);
    return 0;
}
    
/** @} */
    
     
