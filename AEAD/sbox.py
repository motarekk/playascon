# understanding ASCON's Sbox by an example
# implementing ASCON substitution layer using both sbox lookup table (LUT) and bitsliced form and comparing the results which must be the same
# see Sbox bitsliced form instructions at: https://ascon.iaik.tugraz.at/images/sbox_instructions.c

# === helper functions === #
# zero padding
def pad(x, y):
    while len(x) < y:
        x = '0' + x
      
    return x

# putting state in columns
def in_columns(S):
    columns = [''] * 64

    for raw in range(len(S)):
        for i in range(len(columns)):
            columns[i] += S[raw][i] 

    return columns

# putting state in raws
def in_raws(S_columns):
    raws = [''] * 5

    for column in range(len(S_columns)):
        for i in range(len(raws)):
            raws[i] += S_columns[column][i]

    return raws

# convert state from binary to hexadecimal
def state_to_hex(S):
    S_hex = [''] * len(S)

    for i in range(len(S)):
        S_hex[i] = hex(int(S[i], 2))

    return S_hex

# convert state from hexadecimal to binary
def state_to_bin(S):
    # apply propper padding
    padding = 0
    if len(S) == 5:
        padding = 64
    else: padding = 5
    
    S_bin = [''] * len(S)

    for i in range(len(S)):
        S_bin[i] = pad(bin(int(S[i], 16)).replace('0b', ''), padding)

    return S_bin

# convert state from binary to decimal
def state_to_dec(S):
    S_dec = [''] * len(S)

    for i in range(len(S)):
        S_dec[i] = int(S[i], 2)

    return S_dec

# === end of helper functions === #

# state raws in binary (example)
x0= pad(bin(0x18b054dd867a0027).replace('0b', ''), 64)
x1= pad(bin(0x9a894dfcca632c14).replace('0b', ''), 64)
x2= pad(bin(0x935617eaf6b879cf).replace('0b', ''), 64)
x3= pad(bin(0xe15cb755138fb880).replace('0b', ''), 64)
x4= pad(bin(0x21de40a99935ccdb).replace('0b', ''), 64)

S_raws = [x0, x1, x2, x3, x4]

# state 5-bits columns
S_columns = in_columns(S_raws)

# visualizing state raws & columns
print(f"state raws: {S_raws}\n")
print(f"state columns: {S_columns}\n")

# performing substitution layer using Sbox lookup table (LUT)
def sbox(S_columns):
    S_columns_hex = state_to_hex(S_columns)
    sbox = ['4', 'b', '1f', '14', '1a', '15', '9', '2', '1b', '5', '8', '12', '1d', '3', '6', '1c', '1e', '13','7', 'e', '0', 'd', '11', '18', '10', 'c', '1', '19', '16', 'a', 'f', '17']
    output = [''] * 64

    for i in range(len(S_columns_hex)):
        for j in range(len(sbox)):
            if S_columns_hex[i] == hex(j):
                output[i] = sbox[j]
    
    return output

# performing substitution layer using bitsliced form
# referece: https://ascon.iaik.tugraz.at/images/sbox_instructions.c
def sbox_simplified(state):
    # convert S from binary to decimal
    for i in range(len(state)):
        state[i] = int(state[i], 2)

    state[0] ^= state[4]
    state[4] ^= state[3]
    state[2] ^= state[1]

    # this line summarizes the NOR & ANDing operations for all raws 
    T = [(state[i] ^ 0xFFFFFFFFFFFFFFFF) & state[(i+1)%5] for i in range(5)]

    for i in range(5):
        state[i] ^= T[(i+1)%5]
    state[1] ^= state[0]
    state[0] ^= state[4]
    state[3] ^= state[2]
    state[2] ^= 0XFFFFFFFFFFFFFFFF 

    return state

# proof that sbox LUT result == bitsliced sboxing result
state_after_sbox = state_to_dec(in_raws(state_to_bin(sbox(S_columns))))
state_after_simplified_sbox = sbox_simplified(S_raws)

if state_after_sbox == state_after_simplified_sbox:
    print("True")
else:
    print("False")
# result: True
