# playascon
### Understanding, implementing, documenting and playing with ASCON cipher, the state of the art of Lightweight Cryptography (LWC).<br><br>

### What is ASCON?
* ####  Ascon is a lightweight cryptographic family that includes Authenticated Encryption with Associated Data (AEAD), Hashing, and Message Authentication Code (MAC) algorithms.
* #### It has been selected as the primary choice for lightweight authenticated encryption in the final portfolio of the CAESAR competition (2014–2019).
* #### It has been selected by the US National Institute of Standards and Technology (NIST) for future standardization of the lightweight cryptography (Feb, 2023).<br><br>


<img width="650" alt="ascon-family" src="https://github.com/motarekk/playascon/assets/104282801/0b0cf288-fd7c-4f14-9369-356168141dde">


### Some features I like about ASCON
* #### It processes data like a sponge (absorbing/squeezing), hence its name is Ascon (lookup the ascon canal system). 
* #### One-pass and inverse free.
* #### No need for key scheduling.
* #### No need for using lookup tables for Sbox in the implementation.<br><br>
<img width="250" alt="ascon-canal-system" src="https://github.com/motarekk/playascon/assets/104282801/c11047eb-f4de-44e1-b5ae-2392a4fe7c2a">

### Important links:
[1] Ascon official site:
https://ascon.iaik.tugraz.at/

[2] Ascon submission for NIST (2021):
https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf

[3] The sponge and duplex constructions:
https://keccak.team/sponge_duplex.html

[4] Python implementation of Ascon by Maria Eichlseder (one of the authors):
https://github.com/meichlseder/pyascon/

[5] My YouTube channel (I do livestreams):
https://www.youtube.com/@motarekk/streams
