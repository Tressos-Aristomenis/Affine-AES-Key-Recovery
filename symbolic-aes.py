from sage.all_cmdline import *
import os, aes

def vector2matrix(v, n):
  return Matrix(PR, n, n, v)

def list2vector(l):
  return vector(PR, 16, l)

def xor(a, b):
  return [_a+_b for _a,_b in zip(a,b)]

def rot_word(w):
  return list(w[1:]) + [w[0]]

def expand_key(key):
  ### ONLY IN AES-128 ###
  N = 4
  R = 11
  #######################
  rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
  rcon = list(map(F.from_integer, rcon))

  rk = []

  for i in range(4*R):
    if i < N:
      rk.append(list(key[i*4:i*4+4]))
    elif i >= N and i % N == 0:
      word = rk[i-1]
      word = rot_word(word)
      # substitute word is missing since there is no SBOX
      word = xor(rk[i-N], word)
      word = xor(word, [rcon[i//N - 1], 0, 0, 0])
      rk.append(word)
    else:
      word = xor(rk[i-N], rk[i-1])
      rk.append(word)

  # group round keys per round
  rk = [sum(rk[i:i+4], []) for i in range(0, len(rk), 4)]
  return rk

def add_round_key(p, k):
  return xor(p, k)

def shift_rows(s):
  # according to wikipedia, state matrix is represented column-wise
  return [
    s[0], s[4], s[8], s[12],
    s[5], s[9], s[13], s[1],
    s[10], s[14], s[2], s[6],
    s[15], s[3], s[7], s[11]
  ]

def mix_columns(s):
  fixed = [[2,3,1,1], [1,2,3,1], [1,1,2,3], [3,1,1,2]]
  fixed = [list(map(F.from_integer, block)) for block in fixed]
  fixed = Matrix(PR, fixed)
  v = vector2matrix(s, 4)
  mc = [fixed*col for col in v.columns()]
  return [*mc[0]] + [*mc[1]] + [*mc[2]] + [*mc[3]]
  
def symbolic_encrypt(pt, key):
  rk = expand_key(key)

  state = list2vector([F.from_integer(p) for p in pt])
  state = add_round_key(state, rk[0])

  for i in range(1, 10):
    # skip sub_bytes
    state = shift_rows(state)
    state = mix_columns(state)
    state = add_round_key(state, rk[i])

  state = shift_rows(state)
  # due to shift rows, state is represented column-wise [s0, s4, s8, s12, s1, s5, s9, s13, ...] while round key is represented row-wise [k0, k1, k2, k3, k4, ..., k15]
  # we need to transpose the state after the last shift_rows so that we can add with the last round key
  state = vector2matrix(state, 4).transpose().list()
  state = add_round_key(state, rk[10])

  return state

def recover_key(real_key):
  key = PR.gens()
  P0 = bytes.fromhex('00' * 16)

  sym_ct = symbolic_encrypt(P0, key)
  # example of symbolic row : (z^5 + z^3 + z^2 + z + 1)*k0 + (z^3)*k1 + (z^5 + z^3 + z^2 + z + 1)*k2 + ... + (z^6 + z^5 + z^4 + z^2 + z + 1)*k15 + (z^7 + z^4 + z^3 + z)

  A = []
  B = []
  for row in sym_ct:
    # coefficients() returns only non-zero coefficients so 0 might be skipped
    kcoeffs = [row.coefficient(key[i]) for i in range(16)]
    A.append(kcoeffs)
    B.append(row.constant_coefficient())

  A = vector2matrix(A, 16)
  B = list2vector(B)

  E0 = aes.encrypt(real_key, P0)
  E0V = list2vector([F.from_integer(e) for e in E0])

  # E(0) = A*key + B ==>
  # key = A^(-1)*(E(0) - B)
  key = A.inverse()*(E0V - B)

  key = eval(str(key).replace('^','**')) # ugly trick to convert FractionField Elements => GF elements
  key = bytes([k.to_integer() if k > 1 else k for k in key])

  assert P0 == aes.decrypt(key, E0)

  return key

if __name__ == '__main__':
  ### Symbolic Execution Setup ###
  F = GF(2**8, 'z', modulus=x**8+x**4+x**3+x+1)
  z = F.gen()
  ki = ','.join([f'k{i}' for i in range(16)])
  PR = F[ki]
  ################################

  FLAG = b'crypto{good_job}'
  real_key = os.urandom(16)
  enc_flag = aes.encrypt(real_key, FLAG)

  recovered_key = recover_key(real_key)

  assert FLAG == aes.decrypt(recovered_key, enc_flag)

  print(f'[+] recovered key = {recovered_key.hex()}')