import random
from lib.crypt import *


client_private_key, client_public_key = generate_keys()
server_private_key, server_public_key = generate_keys()


m0 = random.getrandbits(256)
r0 = random.getrandbits(256)

# Client
chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)
print("init chameleon hash x:", chameleon_hash.x())
print("init chameleon hash y:", chameleon_hash.y())

print("Chameleon hash: ", chameleon_hash)

message = "nagyonjoezAszagdogaaaa"
message_bytes = message.encode()

converted_message = calculate_message_format(message_bytes)

encrypted_message = m_encryption(converted_message, client_private_key, server_public_key)

print("Encrypted m__: ", encrypted_message)

encrypted_r = r_encryption(converted_message, m0, r0, client_private_key)

print("Encrypted r__: ", encrypted_r)


# Server part
print(chameleon_hash_challange(encrypted_message, encrypted_r, client_public_key, chameleon_hash))

##################################################
# import random
# from lib.crypt import *

# def string_to_bigint(s):
#     byte_array = s.encode('utf-8')  
#     big_int = int.from_bytes(byte_array, byteorder='big')
#     return big_int

# def bigint_to_string(n):
#     byte_array = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
#     return byte_array.decode('utf-8')


# def bytes_to_bigint(b):
#     return int.from_bytes(b, byteorder='big')

# def bigint_to_bytes(n, length = 64):
#     return n.to_bytes(length, byteorder='big')

# def sha256_int(n):
#     return hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).digest()
# def xor_bytes(bytes1, bytes2):
#     if len(bytes1) > len(bytes2):
#         return bytes(bytes1[i] ^ bytes2[i % len(bytes2)] for i in range(len(bytes1)))
#     if len(bytes2) > len(bytes1):
#         return bytes(bytes2[i] ^ bytes1[i % len(bytes1)] for i in range(len(bytes2)))
#     return bytes(a ^ b for a, b in zip(bytes1, bytes2))
    
# def generate_keys():
#   private_key = ecdsa.SigningKey.generate(curve=CURVE)
#   public_key= private_key.get_verifying_key()

#   return private_key.privkey.secret_multiplier, public_key.pubkey.point

# client_private_key, client_public_key = generate_keys()
# server_private_key, server_public_key = generate_keys()

# print(dir(server_public_key))
# common_point = client_private_key * server_public_key


# m0 = random.getrandbits(256)
# r0 = random.getrandbits(256)

# # Client
# #chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)
# ch = (m0 + r0 * client_private_key)* CURVE.generator

# print('r0',r0)
# print('m0',m0)
# print("pk",client_private_key)
# print("ch",ch.x(),ch.y())
# print("---------------------------------------------")
# m = string_to_bigint("nagyonjoezAszagdogaaaa||"+str(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())))

# delta = random.getrandbits(256)
# delta_hash = sha256_int(delta)
# private_key_mult_inverse = pow(client_private_key, -1, CURVE.order)

# enc_m = xor_bytes(delta_hash, bigint_to_bytes(m))
# m_send = bytes_to_bigint(xor_bytes(delta_hash, bigint_to_bytes(m)))


# x_common = bigint_to_bytes(common_point.x(), 32)
# delta_bytes = bigint_to_bytes(delta, 32)

# delta_xor_commonkey = xor_bytes(delta_bytes, x_common)

# r_send = (r0 - (m_send-m0) * private_key_mult_inverse) % CURVE.order
# ch2 = (m_send + r_send * client_private_key)* CURVE.generator

# print("d",delta)
# print("m ",m_send)
# print("r ",r_send)
# print("ch2",ch2.x(),ch2.y())
# print("d^k",delta_xor_commonkey)
# print("---------------------------------------------")

# common_point_svr = server_private_key * client_public_key
# x_common_svr = bigint_to_bytes(common_point_svr.x(), 32)

# delta_svr = bytes_to_bigint(xor_bytes(delta_xor_commonkey, x_common_svr))


# delta_hash =  sha256_int(delta_svr)
# dec_m = xor_bytes(delta_hash, enc_m)

# print(dec_m)

# """
# message = "nagyonjoezAszagdogaaaa"
# message_bytes = message.encode()

# converted_message = calculate_message_format(message_bytes)

# encrypted_message = m_encryption(converted_message, client_private_key, server_public_key)

# print("Encrypted m__: ", encrypted_message)

# encrypted_r = r_encryption(converted_message, m0, r0, client_private_key)

# print("Encrypted r__: ", encrypted_r)


# # Server part
# print(chameleon_hash_challange(encrypted_message, encrypted_r, client_public_key, chameleon_hash))"""