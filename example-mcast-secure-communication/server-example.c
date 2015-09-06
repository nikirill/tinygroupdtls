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

/* Define which resources to include to meet memory constraints. */
#define REST_RES_HELLO 1
#define REST_RES_LEDS 0
#define REST_RES_BATTERY 0

#include "erbium.h"

#if defined (PLATFORM_HAS_BUTTON)
#include "dev/button-sensor.h"
#endif
#if defined (PLATFORM_HAS_LEDS)
#include "dev/leds.h"
#endif
#if defined (PLATFORM_HAS_BATTERY)
#include "dev/battery-sensor.h"
#endif

/* For CoAP-specific example: not required for normal RESTful Web service. */
#if WITH_COAP == 13
#include "er-coap-13.h"
#else
#warning "Erbium example without CoAP-specifc functionality"
#endif /* CoAP-specific example */

#define DEBUG 0
#if DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#define PRINT6ADDR(addr) printf("[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7], ((uint8_t *)addr)[8], ((uint8_t *)addr)[9], ((uint8_t *)addr)[10], ((uint8_t *)addr)[11], ((uint8_t *)addr)[12], ((uint8_t *)addr)[13], ((uint8_t *)addr)[14], ((uint8_t *)addr)[15])
#define PRINTLLADDR(lladdr) printf("[%02x:%02x:%02x:%02x:%02x:%02x]",(lladdr)->addr[0], (lladdr)->addr[1], (lladdr)->addr[2], (lladdr)->addr[3],(lladdr)->addr[4], (lladdr)->addr[5])
#else
#define PRINTF(...)
#define PRINT6ADDR(addr)
#define PRINTLLADDR(addr)
#endif

#define REMOTE_PORT            UIP_HTONS(COAP_DEFAULT_PORT)
#define LOCAL_PORT             UIP_HTONS(COAP_DEFAULT_PORT)

#ifdef WITH_DTLS
#define REMOTE_PORT_SECURE     UIP_HTONS(COAP_DEFAULT_PORT+1)
#define LOCAL_PORT_SECURE      UIP_HTONS(COAP_DEFAULT_PORT+1)

#define TA_PSK_IDENTITY     "Client_identity"
#define TA_PSK_IDENTITY_LEN 15
#define TA_PSK_KEY 	        "secretPSK"
#define TA_PSK_KEY_LEN	     9


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

#if defined(WITH_MULTICAST) && defined(WITH_DTLS)
void secure_group_creation(const session_t *mcast_session) {
  dtls_group_t *group = NULL;
  dtls_group_sender_t *sender = NULL;
  session_t origin;
  unsigned char id_sender = 1;
  unsigned char id_group = 3;
  dtls_peer_type role = DTLS_SERVER;

  /**< Creating a DTLS group with the given secure session and the security parameters */
  group = dtls_new_group(mcast_session);
  if (!group) {
      PRINTF("cannot create DTLS group\r\n");
  }
  group->role = role;

  /** preparing a session to create sender */
  uip_ipaddr_t client_addr;
  uip_ip6addr(&client_addr, 0xfe80, 0, 0, 0, 0x060f, 0x07b2, 0x0012, 0x4b00);
  uip_ipaddr_copy(&origin.addr, &client_addr);
  origin.port = REMOTE_PORT_SECURE;
  origin.size = sizeof(origin.addr) + sizeof(origin.port);
  origin.ifindex = 1;

  #ifdef WITH_GROUP_RESPONSE
  group->group_id = id_group;
  #endif // WITH_GROUP_RESPONSE

  sender = dtls_new_group_sender(&origin, id_sender);

  if (!sender) {
      PRINTF("cannot create group sender\r\n");
  } else {
      PRINTF("Created new sender with id %u, seq %u and epoch %u%u\r\n", (unsigned int)sender->id, (unsigned int)sender->mul_rseq[4], sender->epoch[0], sender->epoch[1]);
  }
  dtls_add_group_sender(group, sender);

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



/*---------------------------------------------------------------------------*/
static void
print_local_addresses(void)
{
  int i;
  uint8_t state;

  PRINTF("Server IPv6 addresses: ");
  for(i = 0; i < UIP_DS6_ADDR_NB; i++) {
    state = uip_ds6_if.addr_list[i].state;
    if(uip_ds6_if.addr_list[i].isused &&
       (state == ADDR_TENTATIVE || state == ADDR_PREFERRED)) {
      PRINT6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      PRINTF("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/

/******************************************************************************/
#if REST_RES_HELLO
/*
 * Resources are defined by the RESOURCE macro.
 * Signature: resource name, the RESTful methods it handles, and its URI path (omitting the leading slash).
 */
#ifdef WITH_DTLS
RESOURCE(helloworld, METHOD_GET | IS_SECURE, "hello", "title=\"Hello world: ?len=0..\";rt=\"Text\"");
#else
RESOURCE(helloworld, METHOD_GET, "hello", "title=\"Hello world: ?len=0..\";rt=\"Text\"");
#endif
/*
 * A handler function named [resource name]_handler must be implemented for each RESOURCE.
 * A buffer for the response payload is provided through the buffer pointer. Simple resources can ignore
 * preferred_size and offset, but must respect the REST_MAX_CHUNK_SIZE limit for the buffer.
 * If a smaller block size is requested for CoAP, the REST framework automatically splits the data.
 */
void
helloworld_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  const char *len = NULL;
  /* Some data that has the length up to REST_MAX_CHUNK_SIZE. For more, see the chunk resource. */
  char const * const message = "Hello World! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxy";
  int length = 12; /*           |<-------->| */

  /* The query string can be retrieved by rest_get_query() or parsed for its key-value pairs. */
  if (REST.get_query_variable(request, "len", &len)) {
    length = atoi(len);
    if (length<0) length = 0;
    if (length>REST_MAX_CHUNK_SIZE) length = REST_MAX_CHUNK_SIZE;
    memcpy(buffer, message, length);
  } else {
    memcpy(buffer, message, length);
  }

  REST.set_header_content_type(response, REST.type.TEXT_PLAIN); /* text/plain is the default, hence this option could be omitted. */
  REST.set_header_etag(response, (uint8_t *) &length, 1);
  REST.set_response_payload(response, buffer, length);
}
#endif

/******************************************************************************/
#if REST_RES_BATTERY
/* A simple getter example. Returns the reading from light sensor with a simple etag */
RESOURCE(battery, METHOD_GET, "sensors/battery", "title=\"Battery status\";rt=\"Battery\"");
void
battery_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  int battery = battery_sensor.value(0);

  const uint16_t *accept = NULL;
  int num = REST.get_header_accept(request, &accept);

  if ((num==0) || (num && accept[0]==REST.type.TEXT_PLAIN))
  {
    REST.set_header_content_type(response, REST.type.TEXT_PLAIN);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "%d", battery);

    REST.set_response_payload(response, (uint8_t *)buffer, strlen((char *)buffer));
  }
  else if (num && (accept[0]==REST.type.APPLICATION_JSON))
  {
    REST.set_header_content_type(response, REST.type.APPLICATION_JSON);
    snprintf((char *)buffer, REST_MAX_CHUNK_SIZE, "{'battery':%d}", battery);

    REST.set_response_payload(response, buffer, strlen((char *)buffer));
  }
  else
  {
    REST.set_response_status(response, REST.status.NOT_ACCEPTABLE);
    const char *msg = "Supporting content-types text/plain and application/json";
    REST.set_response_payload(response, msg, strlen(msg));
  }
}
#endif /* PLATFORM_HAS_BATTERY */
/*---------------------------------------------------------------------------*/

PROCESS(rest_server_example, "Erbium Example Server");
AUTOSTART_PROCESSES(&rest_server_example);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rest_server_example, ev, data)
{
  uip_ipaddr_t server_ipaddr;
  uip_ds6_maddr_t *rv;

  PROCESS_BEGIN();

  uip_ip6addr(&server_ipaddr, 0xff1e, 0, 0, 0, 0, 0, 0x89, 0xabcd);
  rv = uip_ds6_maddr_add(&server_ipaddr);

  if(rv) {
	PRINTF("Joined multicast group ");
	PRINT6ADDR(&uip_ds6_maddr_lookup(&server_ipaddr)->ipaddr);
	PRINTF("\n");
  }

  print_local_addresses();

#ifdef WITH_DTLS
  dtls_set_log_level(LOG_DEBUG);
  set_dtls_handler(get_psk_key, NULL);
#endif /* WITH_DTLS */

  PRINTF("\r\nStarting Erbium Example Server\r\n");

  /* Initialize the REST engine. */
  rest_init_engine();

  /** Creating an entry in routing table to able to answer to multicast request with the first message */
  uip_ipaddr_t client_addr;
  uip_lladdr_t lladdr = {{0x04,0x0f,0x07,0xb2,0x00, 0x12,0x4b,0x00}};
  uip_ip6addr(&client_addr, 0xfe80, 0, 0, 0, 0x060f, 0x07b2, 0x0012, 0x4b00);
  uip_ds6_nbr_add(&client_addr, &lladdr, 0, 1);


#ifdef WITH_DTLS
  session_t session;

  /**< Creating a secure session */
  uip_ipaddr_copy(&session.addr, &server_ipaddr);
  session.port = UIP_HTONS(COAP_DEFAULT_PORT+1);
  session.size = sizeof(session.addr) + sizeof(session.port);
  session.ifindex = 1;

  #ifdef WITH_MULTICAST
    secure_group_creation(&session);   /**< Create a DTLS group in case of multicast communication */
  #endif // WITH_MULTICAST
#endif // WITH_DTLS

  /* Activate the application-specific resources. */
#if REST_RES_HELLO
  rest_activate_resource(&resource_helloworld);
#endif

#if REST_RES_BATTERY
  SENSORS_ACTIVATE(battery_sensor);
  rest_activate_resource(&resource_battery);
#endif

  PROCESS_END();
}
