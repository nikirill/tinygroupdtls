/* Function to produce new keys for every listener
 * in a group using given group material
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

#include "key_derivation.h"
#include "debug.h"
#include <string.h>
#include <stdio.h>

static void
dtls_iterate_hmac(const unsigned char *key, const size_t klen,
                  const uip_ipaddr_t *ipaddr, const unsigned short port, unsigned char *result) {

    dtls_hmac_context_t *ctx;
    unsigned char data[DTLS_HMAC_BLOCKSIZE];

    dtls_hmac_storage_init();
    ctx = dtls_hmac_new(key, klen);
    int datalen = sizeof(*ipaddr) + sizeof(port);

    memset(data, 0, DTLS_HMAC_BLOCKSIZE);
    memcpy(data, ipaddr, sizeof(*ipaddr));
    memcpy(data+sizeof(*ipaddr), &port, sizeof(port));

    dtls_hmac_update(ctx, data, datalen);
    dtls_hmac_finalize(ctx, result);

    dtls_hmac_free(ctx);
}

void
dtls_hmac_keys(dtls_group_t *group, uip_ipaddr_t *ipaddr, unsigned short port) {
    debug("dtls_hmac_keys(dtls_group_t *group, uip_ipaddr_t *ipaddr, int port)\r\n");

    unsigned char result[DTLS_HMAC_DIGEST_SIZE];
    unsigned char key[DTLS_HMAC_BLOCKSIZE];
    const size_t keylen = 2 * DTLS_KEY_LENGTH; /**< Length clientWrite + serverWrite */

    memset(key, 0, keylen);
    memcpy(key, dtls_kb_client_write_key(&group->security_params, group->role), keylen); /**< Key for HMAC is concatenation clientWrite + serverWrite */

    if (group->role == DTLS_SERVER) {

        memset(result, 0, DTLS_HMAC_DIGEST_SIZE);
        dtls_iterate_hmac(key, keylen, ipaddr, port, result);
        memcpy(dtls_kb_server_write_key(&group->security_params, group->role), result+16, dtls_kb_key_size(&group->security_params, group->role)); // Server Write
        memcpy(dtls_kb_server_mac_secret(&group->security_params, group->role), result, dtls_kb_mac_secret_size(&group->security_params, group->role)); // Server Write MAC
    }

    if (group->role == DTLS_CLIENT) {

        dtls_group_listener_t *l;
        session_t listsess;

        memcpy(&listsess.addr, ipaddr, sizeof(*ipaddr));
        listsess.port = port;
        listsess.size = sizeof(listsess.addr) + sizeof(listsess.port);
        listsess.ifindex = 1;

        l = dtls_get_group_listener(group, &listsess);
        if (!l) {
            debug("Cannot find the listener!\r\n");
        }

        memset(result, 0, DTLS_HMAC_DIGEST_SIZE);
        dtls_iterate_hmac(key, keylen, &l->sess.addr, l->sess.port, result);
        memcpy(dtls_kb_server_write_key(l, group->role), result+16, dtls_kb_key_size(&group->security_params, group->role));  // Server Write
        memcpy(dtls_kb_server_mac_secret(l, group->role), result, dtls_kb_mac_secret_size(&group->security_params, group->role));

        l->read_cipher = dtls_cipher_new(group->security_params.cipher,
                                              dtls_kb_server_write_key(l, group->role),
                                              dtls_kb_key_size(l, group->role));
        if (!l->read_cipher) {
              debug("Cannot create a read cipher!\r\n");
        }
    }
}
