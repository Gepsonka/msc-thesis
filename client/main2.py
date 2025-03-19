from lib.crypt import *
import time
import random

KEY_SIZE_BIT = 256

client_private_key, client_public_key = generate_keys()
server_private_key, server_public_key = generate_keys()

common_point = client_private_key * server_public_key


m0 = random.getrandbits(KEY_SIZE_BIT)
r0 = random.getrandbits(KEY_SIZE_BIT)

# Client
chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)

print("chameleon hash: ", chameleon_hash.x(), chameleon_hash.y())
m = string_to_bigint("asdasdasd" + str(int(time.time())))

delta = random.getrandbits(KEY_SIZE_BIT)
delta_hash = sha256_int(delta)
private_key_mult_inverse = pow(client_private_key, -1, CURVE.order)

m_send, delta_xor_commonkey = encrypt_m(m,delta, common_point)
r_send = encrypt_r(m_send, m0, r0, private_key_mult_inverse)

server_chameleon_h = server_chameleon_hash(m_send, r_send, client_public_key)

print("server_chameleon_h", server_chameleon_h.x(), server_chameleon_h.y())

challange = chameleon_hash_challange(chameleon_hash, server_chameleon_h)
print(challange)

common_point_svr = server_private_key * client_public_key
x_common_svr = bigint_to_bytes(common_point_svr.x(), 32)

delta_svr = bytes_to_bigint(xor_bytes(delta_xor_commonkey, x_common_svr))

delta_hash =  sha256_int(delta_svr)
dec_m = xor_bytes(delta_hash, bigint_to_bytes(m_send))

print(dec_m)


if challange:
  srv_common_point = srv_common_point(server_private_key, client_public_key)
  srv_delta_hash = srv_delta(delta_xor_commonkey, srv_common_point)
  dec_m = decrypt_m(bigint_to_bytes(m_send), srv_delta_hash)

  print(dec_m)




