# tinygroupdtls
Lightweigh DTLS implementation with an extension for secure group communication

This is an extension to TinyDTLS library by Olaf Bergmann shipped with Contiki OS. The version corresponds to the Instant Contiki 2.7 image.

The purpose of the extension is to make it possible to secure multicast messages and unicast responses to these multicast messages. Full description of how the protection mechanism works can be found in document [1].

Protection of multicast messages is implemented according to the idea presented by DICE Working group of IETF [2].
A mechanism for protection of unicast responses to multicast requests is intially porposed by M.Tiloca in [3] and improved during the work.



[1] http://kth.diva-portal.org/smash/get/diva2:847246/FULLTEXT01.pdf
[2] https://datatracker.ietf.org/doc/draft-keoh-dice-multicast-security/
[3] http://soda.swedish-ict.se/5709/1/Tiloca_SIN2014.pdf
