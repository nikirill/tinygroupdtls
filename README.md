# tinygroupdtls
Lightweigh DTLS implementation with an extension for secure group communication

This is an extension to TinyDTLS library by Olaf Bergmann shipped with Contiki OS. The version corresponds to the Instant Contiki 2.7 image.

The purpose of the extension is to make it possible to secure multicast messages and unicast responses to these multicast messages. Full description of how the protection mechanism works can be found in document [1].

Protection of multicast messages is implemented according to the idea presented by DICE Working group of IETF [2].
A mechanism for protection of unicast responses to multicast requests is intially porposed by M.Tiloca in [3] and improved during the work.

1. Protection of multicast messages can be turned by defining it in a config file of an application as

#define WITH_MUTLICAST 1

which makes code related to multicast protection of tinygroupdtls being executed. If there are response messages from multicast listeners in this mode, the responses can be protected using established end-to-end dtls sessions with the multicast client.
'example-mcast-secure-communication' uses this scenario.

2. Additional functionality for protection of unicast responses to a mutlicast request using group security material can be turned on by defining additionally

#define WITH_GROUP_RESPONSE 1

Also, NOTE that compilation command needs to include this flag. In Contiki, a compilation command for cc2538dk platform would look like

	make TARGET=cc2538dk WITH_GROUP_RESPONSE=1

'example-full-secure-group-communication' uses this scenario.

In the both aforementioned examples, a multicast client sends a 'hello' request as a multicast message protected using group security material. Servers answer with a string "Hello World!" protected using either unicast security material in the first scenario or group security in the second scenario. The examples are to be used in Contiki OS.

[1] http://kth.diva-portal.org/smash/get/diva2:847246/FULLTEXT01.pdf
[2] https://datatracker.ietf.org/doc/draft-keoh-dice-multicast-security/
[3] http://soda.swedish-ict.se/5709/1/Tiloca_SIN2014.pdf
