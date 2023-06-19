#!/usr/bin/env python3

"""
# === file description === #
# explanatory-documented implementation of Ascon-128 AEAD encryption & decryption
# === By: Mohamed Tarek, aka. motarek === #
# LinkedIn: https://www.linkedin.com/in/mohamed-tarek-159a821ba/
# YouTube (livestreams): https://www.youtube.com/@motarekk/streams

# === some notes about this file === #
# Ascon family includes AEAD, hash, and mac algorithms. This file is an implementation for AEAD only
# Also, Ascon has 3 AEAD variants, this file is only for Ascon-128 variant
# AEAD = Authenticated Encryption with Associated Data
# Ascon submission paper: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
# original pyascon implementation: https://github.com/meichlseder/pyascon
# this file is meant to be a quick hands on Ascon-128 encryption/decryption

# === Ascon core steps === #
# initialize > associated data > plaintext/ciphertext > finalization

# === Ascon parameters === #
# S = ascon state = 64 columns * 5 raws = 320 bits
# data block size = rate (r) = 1st raw of the state = 64 bits
# iv = 64 bits = 80400C0600000000
# key size = 128 bits
# nonce = 128 bits
# tag = 128 bits
"""

def ascon_encrypt(key, nonce, associateddata, plaintext): # input
    # make sure parameters are within the correct ranges
    assert(len(key) == 16 and len(nonce) == 16) 
    
    # parameters
    S = [0, 0, 0, 0, 0]    # state rows
    a = 12  # initial & final rounds
    b = 6   # intermediate rounds
    rate = 8    # bytes

    # process
    ascon_initialize(S, a, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    ciphertext = ascon_process_plaintext(S, b, rate, plaintext)
    tag = ascon_finalize(S, a, key)
    
    #output = ciphertext (same size as plaintext) + tag (128-bits)
    return ciphertext + tag

### ============================================================================== ###

def ascon_decrypt(key, nonce, associateddata, ciphertext): # input
    # make sure parameters are within the correct ranges
    assert(len(key) == 16 and len(nonce) == 16 and len(ciphertext) >= 16)

    # parameters
    S = [0, 0, 0, 0, 0]    # state raws
    a = 12  # inititial & final rounds
    b = 6   # intermediate rounds
    rate = 8    # bytes

    # process
    ascon_initialize(S, a, key, nonce)
    ascon_process_associated_data(S, b, rate, associateddata)
    plaintext = ascon_process_ciphertext(S, b, rate, ciphertext[:-16])  # ignore the tag (last 16 bytes)
    tag = ascon_finalize(S, a, key)

    # output 
    if tag == ciphertext[-16:]: # check the tag for authentication (last 16 bytes)
        return plaintext
    else:
        return None
    
### ============================================================================== ###

def ascon_initialize(S, a, key, nonce): 
    iv = bytes.fromhex('80400c0600000000') 
    '''
    '80400c0600000000' is a fixed iv for Ascon-128, representing its main paramters as following:
      # 80 -> 128 -> key length (k)
      # 40 -> 64 -> rate (r)
      # 0c -> 12 -> a -> number of initial and final permuations
      # 06 -> 6 -> b -> number of intermediate permutaions 
      # 0000000 = padding
    '''

    initial_sate = iv + key + nonce # initial state = iv (64 bits) + key (128 bits) + nonce (128 bits) = 320 bits = 40 bytes 

    '''
    # filling the initial state block as follows (in decimal):
      1st raw S[0] = iv
      2nd & 3rd raws S[1], S[2] = key
      4rd & 5th raws S[4], S[5] = nonce  
    '''
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(initial_sate)

    # initial permutation of the state
    ascon_permutation(S, a)

    # zero_key = key padded with 0s put before it
    # 0*||K = 24 of zero bytes + 16-byte key = 40 bytes total = 320 bits
    # initialize the zero_key and put it in a block
    zero_key = bytes_to_state(b"\x00" * (40-len(key)) + key)

    # XOR the state with the zero_key
    for i in range(5): S[i] ^= zero_key[i]

### ============================================================================== ###

# ad = associated data
def ascon_process_associated_data(S, b, rate, associateddata): 
    if len(associateddata) > 0:
        # == padding == #
        # associated data is padded by 1 followed by 0s --> 1 || 0s
       
        # length of last block in the raw associated data (before padding)
        ad_lastlen = len(associateddata) % rate 

        # calculate how many zero bytes needed for padding
        ad_zero_bytes = rate - (ad_lastlen % rate) -  1

        # keep in mind that 0x80 = 128 = 10000000 in binary
        ad_padding = bytes([0x80] + [0x00]*ad_zero_bytes)
        ad_padded = associateddata + ad_padding

        # == absorbtion of associated data ==#
        # xor padded associated data with the rate, then permute
        for block in range(0, len(ad_padded), rate):
            S[0] ^= int(ad_padded[block:block+8].hex(), 16)
            ascon_permutation(S, b)
   
    # state is xored with 1 for domain separation --> S ^ (0**319 || 1)
    # we only need to xor 1 with the last raw because first 4 raws will remain unchanged
    S[4] ^= 1

### ============================================================================== ###

def ascon_process_plaintext(S, b, rate, plaintext):
    # == padding == #
    # plaintext is padded by 1 followed by 0s --> 1 || 0s
    # note: we need padding only to be able to calculate the the new rate, otherwise the ciphertext is truncated eventually and the padding is discarded

    # length of last block in the raw plaintext (before padding)
    p_lastlen = len(plaintext) % rate 
    
    # calculate how many zero bytes needed for padding
    p_zero_bytes = (rate - p_lastlen) - 1

    # keep in mind that 0x80 = 128 = 10000000 in binary
    p_padding = bytes([0x80] + [0x00]*p_zero_bytes)
    p_padded = plaintext + p_padding

    # == absorbtion of plaintext & squeezing of ciphertext == #
    # processing of first t-1 blocks (all blocks except the last one)
    ciphertext = bytes([])
    blocks = len(p_padded) - rate # length of plaintext blocks except the last block

    for block in range(0, blocks, rate): # ex: if len(p_padded)=24, p1 = 0 to 8, p2 = 8 to 16,, ignoring the last block which is 16 to 24
        S[0] ^= int(p_padded[block:block+8].hex(), 16)  # absorbing = xoring plaintext with the rate 
        ciphertext += S[0].to_bytes(8, 'big') # squeezing
        ascon_permutation(S, b)

    #  processing of last block 
    p_last = int(p_padded[blocks:].hex(), 16)
    S[0] ^= p_last
    # there is no intermediate permutation after the last block 
    
    # last block of ciphertext is truncated to become with the same length of the last block of raw plaintext (before padding) 
    # intended result: len(ciphertext) == len(plaintext)
    ciphertext += S[0].to_bytes(8, 'big')[:p_lastlen]
    return ciphertext

### ============================================================================== ###

def ascon_process_ciphertext(S, b, rate, ciphertext):
    # == padding == #
    # ciphertext is padded by 1 followed by 0s --> 1 || 0s
    
    # length of last block of ciphertext
    c_lastlen = len(ciphertext) % rate  
    
    # calculate how many zero bytes needed for padding
    c_zero_bytes = (rate - c_lastlen) - 1

    # keep in mind that 0x80 = 128 = 10000000 in binary
    c_padding = bytes([0x80] + (c_zero_bytes)*[0x00])
    c_padded = ciphertext + c_padding
    
    # == absorbtion of ciphertext & squeezing of plaintext == #
    # processing of first t-1 blocks  (all blocks except the last one)
    plaintext = bytes([])
    blocks = len(c_padded) - rate # length of ciphetext blocks except the last block

    for block in range(0, blocks, rate):
        Ci = int(c_padded[block:block+8].hex(), 16) # 1 byte block of ciphertext
        plaintext += (S[0] ^ Ci).to_bytes(8, 'big')
        S[0] = Ci # rate will become the ciphertext block
        ascon_permutation(S, b)

    # processing of last block t
    c_last = int(c_padded[blocks:].hex(), 16) # last block
    plaintext += (c_last ^ S[0]).to_bytes(8, 'big')[:c_lastlen]

    # rate = S[0] ^ (plaintext || 1 || 0s)
    padded_plaintext = int((plaintext[:c_lastlen] + c_padding).hex(), 16)
    S[0] ^= padded_plaintext

    return plaintext

### ============================================================================== ###

def ascon_finalize(S, a, key):
    assert(len(key)) == 16

    # == step 1 == #
    # key is padded with 8 bytes of 0s before it & 16 bytes of 0s after it (0**8 || K || 0**16),
    # then it's xored with the state
    # since, only the 2nd & 3rd raw of the state will take effect, we only xor them without implementing the padding step
    S[1] ^= int(key[:8].hex(), 16)
    S[2] ^= int(key[8:].hex(), 16)

    ascon_permutation(S, a)

    # == step 2 ==#
    # 4th & 5th raws of the state are xored with the key, and the result will be the tag
    S[3] ^= int(key[:8].hex(), 16)
    S[4] ^= int(key[8:].hex(), 16)
    tag = (S[3].to_bytes(8, 'big') + S[4].to_bytes(8, 'big'))

    return tag

### ============================================================================== ###
# === ascon permutation === #

def ascon_permutation(S, rounds):
    assert(rounds <= 12)

    for r in range(12-rounds, 12):
        # --- step 1: add round constants --- #
        S[2] ^= (0xf0 - r*0x10 + r*0x1)

        # --- step 2: substitution layer --- #
        # see sbox instructions at: https://ascon.iaik.tugraz.at/images/sbox_instructions.c
        S[0] ^= S[4]
        S[4] ^= S[3]
        S[2] ^= S[1]

        # this line summarizes the NOR & ANDing operations for all raws 
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i+1)%5] for i in range(5)]

        for i in range(5):
            S[i] ^= T[(i+1)%5]
        S[1] ^= S[0]
        S[0] ^= S[4]
        S[3] ^= S[2]
        S[2] ^= 0XFFFFFFFFFFFFFFFF # binary signed 2's complement of ~[S2]
        
        """
        follow this to understand the last line:
        ~ is bitwise NOR operator --> changes sign and substracts one
        ex: if S[2] = 29, then ~S[2] = -30
        we can't deal with negative numbers here, so we take its 2's complement,
        which is done by this operation:
        S[2] ^= 0XFFFFFFFFFFFFFFFF

        Now, notice these numbers carefully:
        ~S[2] = -30 = - 0000000000000000000000000000000000000000000000000000000000011101
        = S[2] ^= 0XFFFFFFFFFFFFFFFF
                    =   1111111111111111111111111111111111111111111111111111111111100010
        didn't get it yet? do this:
        1- study the binary signed 2's complement topic
        2- catch me in my YT stream and ask
        """

        # --- step 3: linear diffusion layer --- #
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2],  1) ^ rotr(S[2],  6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4],  7) ^ rotr(S[4], 41)

### ============================================================================== ###
# === helper functions === #

def bytes_to_state(bytes):
    bytes = bytes.hex()
    return [int(bytes[16*w:16*(w+1)], 16) for w in range(5)]

def rotr(val, r):
    return (val >> r) | ((val & (1<<r)-1) << (64-r))

def get_random_bytes(num):
    from os import urandom
    return (urandom(num))

def hex_print(data):
    for text, val in data:
        print("{text}:{align}0x{val}".format(text=text, val=val, align=(19-len(text))*" "))

### ============================================================================== ###
# === demo aead === #

def demo_aead():
    demo = "=== demo encryption/decryption using Ascon-128 ==="
    associateddata = b'just having fun'
    plaintext      = b'ASCON'
    key = get_random_bytes(16) # ex: b"\xea\xa9\x11\x9a\xa3\xa9\xbd^P\xbc\xcd\xa4\xe1=\x1c\x03"
    nonce = get_random_bytes(16) # ex: b"\x1ae'\xa3fE\xdd\xb9I\x06q\xdc]\x1e\x1e\xbb"

    ciphertext = ascon_encrypt(key, nonce, associateddata, plaintext)
    tag = ciphertext[-16:]
    receivedplaintext = ascon_decrypt(key, nonce, associateddata, ciphertext)

    if receivedplaintext == None: print("verification failed!") | exit()

    print(demo)
    print(f"associated data:    {associateddata}")
    print(f"plaintext:          {plaintext}")
    hex_print([("key", key.hex()),
                ("nonce", nonce.hex()),
                ("ciphertext", ciphertext[:-16].hex()),
                ("tag", tag.hex()),
                ])
    print(f"received plaintext: {receivedplaintext}")

### ============================================================================== ###
# === demo test === #

demo_aead()
