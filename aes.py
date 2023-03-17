N_ROUNDS = 10

def bytes2matrix(text):
  return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
  return bytes([b for r in matrix for b in r])

def shift_rows(s):
  s[0][1], s[1][1], s[2][1], s[3][1] = s[1][1], s[2][1], s[3][1], s[0][1]     # second column
  s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]     # third column
  s[0][3], s[1][3], s[2][3], s[3][3] = s[3][3], s[0][3], s[1][3], s[2][3]     # fourth column

def inv_shift_rows(s):
  s[0][1], s[1][1], s[2][1], s[3][1] = s[3][1], s[0][1], s[1][1], s[2][1]
  s[0][2], s[1][2], s[2][2], s[3][2] = s[2][2], s[3][2], s[0][2], s[1][2]
  s[0][3], s[1][3], s[2][3], s[3][3] = s[1][3], s[2][3], s[3][3], s[0][3]

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1)

def mix_single_column(a):
  # see Sec 4.1.2 in The Design of Rijndael
  t = a[0] ^ a[1] ^ a[2] ^ a[3]
  u = a[0]
  a[0] ^= t ^ xtime(a[0] ^ a[1])
  a[1] ^= t ^ xtime(a[1] ^ a[2])
  a[2] ^= t ^ xtime(a[2] ^ a[3])
  a[3] ^= t ^ xtime(a[3] ^ u)


def mix_columns(s):
  for i in range(4):
    mix_single_column(s[i])


def inv_mix_columns(s):
  # see Sec 4.1.3 in The Design of Rijndael
  for i in range(4):
    u = xtime(xtime(s[i][0] ^ s[i][2]))
    v = xtime(xtime(s[i][1] ^ s[i][3]))
    s[i][0] ^= u
    s[i][1] ^= v
    s[i][2] ^= u
    s[i][3] ^= v

  mix_columns(s)

def add_round_key(s, k):
  return [[t[0] ^ t[1] for t in list(zip(row[0], row[1]))] for row in zip(s, k)]

def expand_key(master_key):
    """
    Expands and returns a list of key matrices for the given master_key.
    """

    # Round constants https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Initialize round keys with raw key material.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Each iteration has exactly as many columns as the key material.
    columns_per_iteration = len(key_columns)
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # Copy previous word.
        word = list(key_columns[-1])

        # Perform schedule_core once every "row".
        if len(key_columns) % iteration_size == 0:
            # Circular shift.
            word.append(word.pop(0))
            # XOR with first byte of R-CON, since the others bytes of R-CON are 0.
            word[0] ^= r_con[i]
            i += 1

        # XOR with equivalent word from previous iteration.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Group key words in 4x4 byte matrices.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]

def encrypt(key, plaintext):
  round_keys = expand_key(key)
  state = bytes2matrix(plaintext)
  
  state = add_round_key(state, round_keys[0])

  for i in range(1, 10):
    shift_rows(state)
    mix_columns(state)
    state = add_round_key(state, round_keys[i])

  shift_rows(state)
  state = add_round_key(state, round_keys[-1])

  return matrix2bytes(state)

def decrypt(key, ciphertext):
    round_keys = expand_key(key)
    state = bytes2matrix(ciphertext)
    
    state = add_round_key(state, round_keys[len(round_keys) - 1])

    for i in range(N_ROUNDS - 1, 0, -1):
        inv_shift_rows(state)
        state = add_round_key(state, round_keys[i])
        inv_mix_columns(state)

    inv_shift_rows(state)
    state = add_round_key(state, round_keys[0])

    return matrix2bytes(state)

if __name__ == '__main__':
  key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
  ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'
  print(decrypt(key, ciphertext))
