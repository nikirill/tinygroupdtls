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

#include "group.h"
#include "debug.h"

/**
 * Initialization related to group communication.
 * First part is to work with memory for group structure,
 * the second is for group sender structure,
 * the third is for group listener structure.
 */

/**
 *  GROUP Functions
 */
#ifndef WITH_CONTIKI
void group_init()
{
}

static inline dtls_group_t *
dtls_malloc_group() {
  return (dtls_group_t *)malloc(sizeof(dtls_group_t));
}

void
dtls_free_group(dtls_group_t *group) {
  dtls_cipher_free(group->security_params.read_cipher);
  dtls_cipher_free(group->security_params.write_cipher);

  free(group);
}
#else /* WITH_CONTIKI */
MEMB(group_storage, dtls_group_t, DTLS_GROUP_MAX);

void
group_init() {
  memb_init(&group_storage);
}

static dtls_group_t *
dtls_malloc_group() {
  return memb_alloc(&group_storage);
}

void
dtls_free_group(dtls_group_t *group) {
  dtls_cipher_free(group->security_params.read_cipher);
  dtls_cipher_free(group->security_params.write_cipher);

  memb_free(&group_storage, group);
}
#endif /* WITH_CONTIKI */

dtls_group_t *
dtls_new_group(const session_t *session) {
  dtls_group_t *group;

  group = dtls_malloc_group();
  if (group) {
    memset(group, 0, sizeof(dtls_group_t));
    memcpy(&group->session, session, sizeof(session_t));

  #ifdef WITH_CONTIKI
    LIST_STRUCT_INIT(group, senders);
    #ifdef WITH_GROUP_RESPONSE
      LIST_STRUCT_INIT(group, listeners);
    #endif // WITH_GROUP_RESPONSE
  #endif // WITH_CONTIKI

    dtls_dsrv_log_addr(LOG_DEBUG, "dtls_new_group", session);
    /* initially allow the NULL cipher */
    group->security_params.cipher = TLS_NULL_WITH_NULL_NULL;
    group->security_params.compression = TLS_COMPRESSION_NULL;
  }
  else
  {
    debug("ERROR: Insufficient memory to create new group\r\n");
  }

  return group;
}


/**
 *  GROUP SENDER Functions
 */
#ifndef WITH_CONTIKI
void group_sender_init()
{
}

static inline dtls_group_sender_t *
dtls_malloc_group_sender() {
  return (dtls_group_sender_t *)malloc(sizeof(dtls_group_sender_t));
}

void
dtls_free_group_sender(dtls_group_sender_t *sender) {
  free(sender);
}
#else /* WITH_CONTIKI */
MEMB(group_sender_storage, dtls_group_sender_t, DTLS_SENDER_MAX);

void
group_sender_init() {
  memb_init(&group_sender_storage);
}

static dtls_group_sender_t *
dtls_malloc_group_sender() {
  return memb_alloc(&group_sender_storage);
}

void
dtls_free_group_sender(dtls_group_sender_t *sender) {
  memb_free(&group_sender_storage, sender);
}
#endif /* WITH_CONTIKI */

dtls_group_sender_t *
dtls_new_group_sender(const session_t *session, const uint8 id) {
  dtls_group_sender_t *sender;

  sender = dtls_malloc_group_sender();
  if (sender) {
      memset(sender, 0, sizeof(dtls_group_sender_t));
      memcpy(&sender->sess, session, sizeof(session_t));
      sender->epoch[1] = 0;
      sender->id = id;
      sender->mul_rseq[4] = 0;
  }
  else
  {
    debug("ERROR: Insufficient memory to create new group sender\r\n");
  }

  return sender;
}


#ifdef WITH_GROUP_RESPONSE
  /**
   *  GROUP LISTENER Functions
   */
   #ifndef WITH_CONTIKI
  void group_listener_init()
  {
  }

  static dtls_group_listener_t *
  dtls_malloc_group_listener() {
    return (dtls_group_listener_t *)malloc(sizeof(dtls_group_listener_t));
  }

  void
  dtls_free_group_listener(dtls_group_listener_t *listener) {
    free(listener);
  }
  #else /* WITH_CONTIKI */
  MEMB(group_listener_storage, dtls_group_listener_t, DTLS_LISTENER_MAX);

  void
  group_listener_init() {
    memb_init(&group_listener_storage);
  }

  static dtls_group_listener_t *
  dtls_malloc_group_listener() {
    return memb_alloc(&group_listener_storage);
  }

  void
  dtls_free_group_listener(dtls_group_listener_t *listener) {
    memb_free(&group_listener_storage, listener);
  }
  #endif /* WITH_CONTIKI */


  dtls_group_listener_t *
  dtls_new_group_listener(const session_t *session) {
    dtls_group_listener_t *listener;

    listener = dtls_malloc_group_listener();
    if (listener) {
      memset(listener, 0, sizeof(dtls_group_listener_t));
      memcpy(&listener->sess, session, sizeof(session_t));
      listener->epoch[1] = 0;
      listener->mul_rseq[4] = 0;
    }
    else
    {
      debug("ERROR: Insufficient memory to create new group listener\r\n");
    }

    return listener;
  }
#endif // WITH_GROUP_RESPONSE
