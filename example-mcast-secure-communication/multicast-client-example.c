/**
 * \file
 *      CoAP CLient example for multicast communication
 * \author
 *      Kirill Nikitin kirill@sics.se
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "contiki.h"
#include "contiki-net.h"

#include "dev/button-sensor.h"

#if WITH_COAP == 13
#include "er-coap-13-engine.h"
#else
#error "CoAP version defined by WITH_COAP not implemented"
#endif

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) PRINTF("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) PRINTF("[%02x:%02x:%02x:%02x:%02x:%02x]",(lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3],(lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#ifdef WITH_MULTICAST
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xff1e, 0, 0, 0, 0, 0, 0x89, 0xabcd);               /** multicast */
#else
#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x060f, 0x2693, 0x0012, 0x4b00)     /** unicast on boards */
//#define SERVER_NODE(ipaddr)   uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x0212, 0x7402, 0x0002, 0x0202)    /** unicast in cooja */
#endif // WITH_MULTICAST


#define LISTENER1(ipaddr) uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x060f, 0x2693, 0x0012, 0x4b00)
#define LISTENER2(ipaddr) uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x040d, 0x7f1c, 0x0012, 0x4b00)
#define LISTENER3(ipaddr) uip_ip6addr(ipaddr, 0xfe80, 0, 0, 0, 0x040e, 0x321c, 0x0012, 0x4b00)


#define REMOTE_PORT            UIP_HTONS(COAP_DEFAULT_PORT)
#define LOCAL_PORT             UIP_HTONS(COAP_DEFAULT_PORT)

#define TOGGLE_INTERVAL 10

#ifdef WITH_DTLS
#define REMOTE_PORT_SECURE     UIP_HTONS(COAP_DEFAULT_PORT+1)
#define LOCAL_PORT_SECURE      UIP_HTONS(COAP_DEFAULT_PORT+1)

#define TA_PSK_IDENTITY       "Client_identity"
#define TA_PSK_IDENTITY_LEN   15
#define TA_PSK_KEY 	          "secretPSK"
#define TA_PSK_KEY_LEN	      9

#define KEYBLOCK_LEN    40
static const unsigned char KEYBLOCK[] = "ClientWriteKey+_ServerWriteKey+_clIVsrIV";

  int
  get_psk_key(
    struct dtls_context_t *ctx,
    const session_t *session,
    const unsigned char *id, size_t id_len,
    const dtls_psk_key_t **result) {
    static const dtls_psk_key_t ta_psk = {
      .id = (unsigned char *)TA_PSK_IDENTITY,
      .id_length = TA_PSK_IDENTITY_LEN,
      .key = (unsigned char *)TA_PSK_KEY,
      .key_length = TA_PSK_KEY_LEN
    };

      *result = &ta_psk;
      return 0;
  }
#endif /*WITH_DTLS*/

PROCESS(coap_client_example, "COAP Client Example");
AUTOSTART_PROCESSES(&coap_client_example);


uip_ipaddr_t server_ipaddr;
uip_ipaddr_t l1addr, l2addr, l3addr;
static struct etimer et;

/* Example URIs that can be queried. */
#define NUMBER_OF_URLS 2
/* leading and ending slashes only for demo purposes, get cropped automatically when setting the Uri-Path */
char* service_urls[NUMBER_OF_URLS] = {"/hello", "battery/"};

static int uri_switch = 0;


#if defined(WITH_MULTICAST) && defined(WITH_DTLS)
void secure_group_creation(const session_t *mcast_session) {
  dtls_group_t *group = NULL;
  dtls_peer_type role = DTLS_CLIENT;
  unsigned char id_sender = 1;

  /**< Creating a DTLS group with the given secure session and the security parameters */
  group = dtls_new_group(mcast_session);
  if (!group) {
      PRINTF("cannot create DTLS group\r\n");
  }
  group->role = role;
  group->epoch[1] = 0;
  group->sender_id = id_sender;
  group->mul_rseq[4] = 0;

  PRINTF("Sender id in group is %u\r\n", (unsigned int)group->sender_id);

  #ifdef WITH_GROUP_RESPONSE
  unsigned char id_group = 3;
  group->group_id = id_group;

  /** creating listeners with given ip addresses */
  uip_ipaddr_t listener_addr;
  LISTENER1(&listener_addr);
  create_listener(group, &listener_addr, REMOTE_PORT_SECURE);
  LISTENER2(&listener_addr);
  create_listener(group, &listener_addr, REMOTE_PORT_SECURE);
  LISTENER3(&listener_addr);
  create_listener(group, &listener_addr, REMOTE_PORT_SECURE);
  #endif // WITH_GROUP_RESPONSE

  memset(&group->security_params, 0, sizeof(dtls_security_parameters_t));
  group->security_params.cipher = TLS_PSK_WITH_AES_128_CCM_8;
  group->security_params.compression = TLS_COMPRESSION_NULL;
  memcpy(&group->security_params.key_block, KEYBLOCK, KEYBLOCK_LEN);
  group->security_params.read_cipher = dtls_cipher_new(group->security_params.cipher,
                                                            dtls_kb_remote_write_key(&group->security_params, group->role),
                                                            dtls_kb_key_size(&group->security_params, group->role));
  if (!group->security_params.read_cipher) {
    PRINTF("Cannot create a read cipher!\r\n");
  }

  group->security_params.write_cipher = dtls_cipher_new(group->security_params.cipher,
                                                             dtls_kb_local_write_key(&group->security_params, group->role),
                                                             dtls_kb_key_size(&group->security_params, group->role));
  if (!group->security_params.write_cipher) {
    PRINTF("Cannot create a write cipher!\r\n");
  }

  dtls_add_group(get_dtls_config(), group);
}
#endif // WITH_MULTICAST && WITH_DTLS


/*---------------------------- PROCESS thread ------------------------------*/
PROCESS_THREAD(coap_client_example, ev, data)
{
  PROCESS_BEGIN();

  uint16_t packet_len;
  uint8_t packet[COAP_MAX_PACKET_SIZE+1];
  uint8_t token[4];
  uint8_t token_len = 4;
  uint8_t i;
  static coap_packet_t request[1]; /* This way the packet can be treated as pointer as usual. */

  PRINTF("\r\nStarting Erbium Multicast Client\r\n");

  SERVER_NODE(&server_ipaddr);
  PRINT6ADDR(&server_ipaddr);
  PRINTF("\r\n");

#ifdef WITH_DTLS
  dtls_set_log_level(LOG_DEBUG);
  set_dtls_handler(get_psk_key, NULL);
#endif // WITH_DTLS

  coap_receiver_init();   /**< receives all CoAP messages */


  /**< UNICAST communication */
  /** Creating an entry in routing table to avoid dropping the first message and initiation of icmp exchange */
  /* first */
  LISTENER1(&l1addr);
  uip_lladdr_t lladdr1 = {{0x04,0x0f,0x26,0x93,0x00,0x12,0x4b,0x00}};
  uip_ds6_nbr_add(&l1addr, &lladdr1, 0, 1);
  /* second */
  LISTENER2(&l2addr);
  uip_lladdr_t lladdr2 = {{0x06,0x0d,0x7f,0x1c,0x00,0x12,0x4b,0x00}};
  uip_ds6_nbr_add(&l2addr, &lladdr2, 0, 1);
  /* third */
  LISTENER3(&l3addr);
  uip_lladdr_t lladdr3 = {{0x06,0x0e,0x32,0x1c,0x00,0x12,0x4b,0x00}};
  uip_ds6_nbr_add(&l3addr, &lladdr3, 0, 1);


#ifdef WITH_DTLS
  /**< Creating a secure group session */
  session_t session;
  uip_ipaddr_copy(&session.addr, &server_ipaddr);
  session.port = REMOTE_PORT_SECURE;
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;

  secure_group_creation(&session);   /**< Create a DTLS group for multicast communication */


  /**< Creating secure unicast sessions for responses */
  /* first listener*/
  uip_ipaddr_copy(&session.addr, &l1addr);
  session.port = REMOTE_PORT_SECURE;
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;
  dtls_connect(get_dtls_config(), &session);    /**< Connect to a remote peer in case of unicast communication */

  etimer_set(&et, 3 * CLOCK_SECOND);
  while (1) {
  		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  		break;
  }

  /* second listener */
  uip_ipaddr_copy(&session.addr, &l2addr);
  session.port = REMOTE_PORT_SECURE;
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;
  dtls_connect(get_dtls_config(), &session);
  etimer_reset(&et);
  while (1) {
  		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  		break;
  }

  /* third listener */
  uip_ipaddr_copy(&session.addr, &l3addr);
  session.port = REMOTE_PORT_SECURE;
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;
  dtls_connect(get_dtls_config(), &session);
  etimer_reset(&et);
  while (1) {
  		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  		break;
  }
#endif /* WITH_DTLS */


  etimer_set(&et, TOGGLE_INTERVAL * CLOCK_SECOND);

  while(1) {
    PROCESS_YIELD();

    if (etimer_expired(&et)) {

      coap_init_message(request, COAP_TYPE_NON, COAP_GET, coap_get_mid());
      coap_set_header_uri_path(request, service_urls[uri_switch]);

      for (i=0; i<token_len; i++) {
          token[i] = random_rand();
      }
      coap_set_header_token(request, token, token_len);

      packet_len = coap_serialize_message(request, packet);

      #ifdef WITH_DTLS
      coap_send_message(&server_ipaddr, REMOTE_PORT_SECURE, LOCAL_PORT_SECURE, packet, packet_len);
      #else
      coap_send_message(&server_ipaddr, REMOTE_PORT, packet, packet_len);
      #endif

      printf("\n--Requesting %s--\n", service_urls[uri_switch]);
      printf("With token ");
      for (i=0; i<token_len; i++) {
          printf("%02X", token[i]);
      }
      printf("\r\n");

/*      uri_switch = (uri_switch+1) % NUMBER_OF_URLS;*/

      etimer_reset(&et);

    }
  }

  PROCESS_END();
}
