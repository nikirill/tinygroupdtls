#ifndef _CONFIG_H_
#define _CONFIG_H_

#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"

//#define WITH_MULTICAST 1  /**< TO MOVE to a project configuration file after implementation is done */
//#define WITH_GROUP_RESPONSE 1  /**< TO MOVE to a project configuration file after implementation is done */

#define WITH_CONTIKI 1

#define HAVE_STRNLEN 1
#define HAVE_SNPRINTF 1

#ifndef DTLS_PEER_MAX
/** The maximum number DTLS peers (i.e. sessions). */
#  define DTLS_PEER_MAX 3
#endif

#ifdef WITH_MULTICAST
#ifndef DTLS_GROUP_MAX
/** The maximum number DTLS groups (i.e. sessions) where a node is included. */
#  define DTLS_GROUP_MAX 1
#endif

#ifndef DTLS_SENDER_MAX
/** The maximum number of senders in DTLS multicast group. */
#define DTLS_SENDER_MAX 1
#endif // DTLS_SENDER_MAX

#ifdef WITH_GROUP_RESPONSE
#ifndef DTLS_LISTENER_MAX
/** The maximum number of listeners in DTLS multicast group. */
#define DTLS_LISTENER_MAX 3
#endif // DTLS_LISTENER_MAX
#endif // WITH_GROUP_RESPONSE
#endif // WITH_MULTICAST

#ifndef DTLS_CIPHER_CONTEXT_MAX
/** The maximum number of cipher contexts that can be used in parallel. */
#ifndef WITH_MULTICAST
#define DTLS_CIPHER_CONTEXT_MAX (2 * DTLS_PEER_MAX)
#else
#define DTLS_CIPHER_CONTEXT_MAX (2 * (DTLS_PEER_MAX + DTLS_GROUP_MAX))
#endif // WITH_MULTICAST
#endif

#ifndef DTLS_HASH_MAX
/** The maximum number of hash functions that can be used in parallel. */
#ifndef WITH_MULTICAST
#  define DTLS_HASH_MAX (3 * DTLS_PEER_MAX)
#else
#  define DTLS_HASH_MAX (3 * DTLS_PEER_MAX + 2 * DTLS_GROUP_MAX)
#endif // WITH_MULTICAST
#endif

/** The maximum buffer size to hold DTLS messages */
#define DTLS_MAX_BUF 100

#include "contiki-conf.h"

#if CONTIKI_TARGET_REDBEE_ECONOTAG
/* Redbee econotags get a special treatment here: endianness is set explicitly */

/* #define BYTE_ORDER UIP_LITTLE_ENDIAN */

#undef HAVE_ASSERT_H
#define assert(x)
#define HAVE_UNISTD_H
#endif /* CONTIKI_TARGET_REDBEE_ECONOTAG */

#ifdef CONTIKI_TARGET_MBXXX
/* ST Microelectronics */

#define BYTE_ORDER 1234
#endif /* CONTIKI_TARGET_MBXXX */

#ifdef CONTIKI_TARGET_MINIMAL_NET
#undef HAVE_ASSERT_H
#define assert(x)
#define HAVE_VPRINTF
#endif /* CONTIKI_TARGET_MINIMAL_NET */

#ifdef CONTIKI_TARGET_CC2538DK
#undef HAVE_ASSERT_H
#define assert(x)
#endif /* CONTIKI_TARGET_CC2538DK */

#if defined(TMOTE_SKY)
/* Need to set the byte order for TMote Sky explicitely */

#define BYTE_ORDER UIP_LITTLE_ENDIAN
#define BYTE_ORDER 1234
typedef int ssize_t;
#undef HAVE_ASSERT_H
#endif /* defined(TMOTE_SKY) */



#ifndef BYTE_ORDER
# ifdef UIP_CONF_BYTE_ORDER
#  define BYTE_ORDER UIP_CONF_BYTE_ORDER
# else
#  error "UIP_CONF_BYTE_ORDER not defined"
# endif /* UIP_CONF_BYTE_ORDER */
#endif /* BYTE_ORDER */

#endif /* _CONFIG_H_ */

