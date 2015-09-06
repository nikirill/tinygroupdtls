all: er-example-server er-example-client


# variable for this Makefile
# configure CoAP implementation (3|7|12|13) (er-coap-07 also supports CoAP draft 08)
WITH_COAP=13
WITH_CONTIKI=1
# variable for Makefile.include
WITH_UIP6=1
# for some platforms
UIP_CONF_IPV6=1
CFLAGS += -DUIP_CONF_IPV6=1


CONTIKI=../..
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"


# linker optimizations
SMALL=1

# REST framework, requires WITH_COAP
ifeq ($(WITH_COAP), 13)
${info INFO: compiling with CoAP-13}
CFLAGS += -DWITH_COAP=13
CFLAGS += -DREST=coap_rest_implementation
CFLAGS += -DUIP_CONF_TCP=0
APPS += er-coap-13-mcast-dtls
endif

CFLAGS += -DWITH_COAP=13 -DWITH_CONTIKI=1 -DUIP_CONF_IPV6=1
CFLAGS += -DUIP_CONF_IPV6_RPL=0
CFLAGS += -DNDEBUG=0
#CFLAGS += -DDEBUG=1
CFLAGS += -DWITH_MULTICAST=1
CFLAGS += -DWITH_GROUP_RESPONSE=1

CFLAGS += -DWITH_DTLS=1
APPS += tinygroupdtls/aes tinygroupdtls/sha2 tinygroupdtls

APPS += erbium


include $(CONTIKI)/Makefile.include


## border router rules
#$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
#	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)
#
#connect-router:	$(CONTIKI)/tools/tunslip6
#	sudo $(CONTIKI)/tools/tunslip6 aaaa::1/64
#
#connect-router-cooja:	$(CONTIKI)/tools/tunslip6
#	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 aaaa::1/64
#
#connect-minimal:
#	sudo ip address add fdfd::1/64 dev tap0
