/* dtls -- basic DTLS implementation with adaptation for group communication
 *
 * Copyright (C) 2015 Kirill Nikitin <kirilln@kth.se>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file group.h
 * @brief information about groups in a DTLS session
 */

#ifndef _GROUP_H_
#define _GROUP_H_

#include "config.h"
#include "global.h"
#include "peer.h"

#include "state.h"
#include "crypto.h"

#ifndef WITH_CONTIKI
#include "uthash.h"
#endif /* WITH_CONTIKI */


/**
 * Basically, Group Security Association.
 * Holds security parameters, transport address, sender_id if it is a client
 * group_id if response protection with individual keys is enabled,
 * list of senders if a server, list of listeners if a client
 */
typedef struct dtls_group_t {
#ifndef WITH_CONTIKI
  UT_hash_handle hh_groups;
#else /* WITH_CONTIKI */
  struct dtls_group_t *next;
#endif /* WITH_CONTIKI */

  session_t session;	       /**< group address and local interface */

  dtls_peer_type role;       /**< denotes if this host is DTLS_CLIENT or DTLS_SERVER */
  uint16 epoch;		           /**< counter for cipher state changes*/
  uint8 sender_id;           /**< denotes sender id of a sender assigned by a group manager for group communication */
  uint40 mul_rseq;           /**< 5-bytes sequence number of last record sent in case of group communication */
  #ifdef WITH_GROUP_RESPONSE
  uint8 group_id;
  #endif // WITH_GROUP_RESPONSE

  dtls_security_parameters_t security_params;

#ifndef WITH_CONTIKI
  dtls_group_sender_t *senders;        /**< senders hash map */
  #ifdef WITH_GROUP_RESPONSE
    dtls_group_listener_t *listeners;  /**< listeners hash map */
  #endif // WITH_GROUP_RESPONSE
#else /* WITH_CONTIKI */
  LIST_STRUCT(senders);     /**< a list structure of senders if there is Contiki */
  #ifdef WITH_GROUP_RESPONSE
    LIST_STRUCT(listeners);
  #endif // WITH_GROUP_RESPONSE
#endif /* WITH_CONTIKI */

  void* custom_data;
} dtls_group_t;


void group_init();

/**
 * Creates a new group for given @p session. The current configuration
 * is initialized with the cipher suite TLS_NULL_WITH_NULL_NULL (i.e.
 * no security at all). This function returns a pointer to the new
 * group or NULL on error. The caller is responsible for releasing the
 * storage allocated for this peer using dtls_free_group().
 *
 * @param session  Multicast address and port number used for group communication, and interface index.
 * @return A pointer to a newly created and initialized group object
 * or NULL on error.
 */
dtls_group_t *dtls_new_group(const session_t *session);


/** Releases the storage allocated to @p group. */
void dtls_free_group(dtls_group_t *group);


/**
 * The dtls_group_sender_t structure to be included in group to keep track
 * on listener's side of sequence numbers for every sender in a group separately
 */
typedef struct dtls_group_sender_t {
#ifndef WITH_CONTIKI
  UT_hash_handle hh_senders;
#else /* WITH_CONTIKI */
  struct dtls_group_sender_t *next;
#endif /* WITH_CONTIKI */

  session_t sess;          /**< session including a source address, port number and interface number of a multicast sender  */
  uint16 epoch;		         /**< counter for cipher state changes*/
  uint8 id;                /**< denotes sender id of a sender assigned by a group manager for group communication */
  uint40 mul_rseq;         /**< 5-bytes sequence number of last record sent in case of group communication */

} dtls_group_sender_t;

/**
* Functions for management of multicast group senders
*/
void group_sender_init();

dtls_group_sender_t *dtls_new_group_sender(const session_t *session, const uint8 id);

void dtls_free_group_sender(dtls_group_sender_t *sender);


#ifdef WITH_GROUP_RESPONSE
/**
 * The dtls_group_listener_t structure to be included in group to keep track
 * on sender's side of sequence numbers for every listener in a group who sends
 * response messages.
 */
typedef struct dtls_group_listener_t {
#ifndef WITH_CONTIKI
  UT_hash_handle hh_listeners;
#else /* WITH_CONTIKI */
  struct dtls_group_listener_t *next;
#endif /* WITH_CONTIKI */

  session_t sess;          /**< session including a source address, port number and interface number of a group listener  */
  uint16 epoch;		         /**< counter for cipher state changes*/
  uint40 mul_rseq;         /**< 5-bytes sequence number of last record sent in case of group communication */

  /**
   * Individual key block and cipher decryption context
   * for every listener with individual ServerWrite key.
   * Derived from common key_block using listener's ip address
   * and port number.
   */
  uint8 key_block[MAX_KEYBLOCK_LENGTH];
  dtls_cipher_context_t *read_cipher;  /**< decryption context */

} dtls_group_listener_t;


/**
* Functions for management of group listeners
*/
void group_listener_init();

dtls_group_listener_t *dtls_new_group_listener(const session_t *session);

void dtls_free_group_listener(dtls_group_listener_t *listener);
#endif // WITH_GROUP_RESPONSE


#endif /* _GROUP_H_ */
