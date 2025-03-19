# import random
# from lib.crypt import *


# client_private_key, client_public_key = generate_keys()
# server_private_key, server_public_key = generate_keys()


# m0 = random.getrandbits(256)
# r0 = random.getrandbits(256)

# # Client
# chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)
# print("init chameleon hash x:", chameleon_hash.x())
# print("init chameleon hash y:", chameleon_hash.y())

# print("Chameleon hash: ", chameleon_hash)

# message = "nagyonjoezAszagdogaaaa"
# message_bytes = message.encode()

# converted_message = calculate_message_format(message_bytes)

# encrypted_message = m_encryption(converted_message, client_private_key, server_public_key)

# print("Encrypted m__: ", encrypted_message)

# encrypted_r = r_encryption(converted_message, m0, r0, client_private_key)

# print("Encrypted r__: ", encrypted_r)


# # Server part
# print(chameleon_hash_challange(encrypted_message, encrypted_r, client_public_key, chameleon_hash))

##################################################
import random
from lib.crypt import *


def string_to_bigint(s):
    byte_array = s.encode("utf-8")
    big_int = int.from_bytes(byte_array, byteorder="big")
    return big_int


def bigint_to_string(n):
    byte_array = n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    return byte_array.decode("utf-8")


def bytes_to_bigint(b):
    return int.from_bytes(b, byteorder="big")


def bigint_to_bytes(n, length=64):
    return n.to_bytes(length, byteorder="big")


def sha256_int(n):
    return hashlib.sha256(
        n.to_bytes((n.bit_length() + 7) // 8, byteorder="big")
    ).digest()


def xor_bytes(bytes1, bytes2):
    if len(bytes1) > len(bytes2):
        return bytes(bytes1[i] ^ bytes2[i % len(bytes2)] for i in range(len(bytes1)))
    if len(bytes2) > len(bytes1):
        return bytes(bytes2[i] ^ bytes1[i % len(bytes1)] for i in range(len(bytes2)))
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))


def generate_keys():
    private_key = ecdsa.SigningKey.generate(curve=CURVE)
    public_key = private_key.get_verifying_key()

    return private_key.privkey.secret_multiplier, public_key.pubkey.point


client_private_key, client_public_key = generate_keys()
server_private_key, server_public_key = generate_keys()

print(dir(server_public_key))
common_point = client_private_key * server_public_key


m0 = random.getrandbits(256)
r0 = random.getrandbits(256)

# Client
chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)
ch = (m0 + r0 * client_private_key) * CURVE.generator

print("r0", r0)
print("m0", m0)
print("pk", client_private_key)
print("ch", ch.x(), ch.y())
print("chameleon hash: ", chameleon_hash.x(), chameleon_hash.y())
print("---------------------------------------------")
m = string_to_bigint("nagyonjoezAszagdogaaaa||" + str(int(time.time())))

delta = random.getrandbits(256)
delta_hash = sha256_int(delta)
private_key_mult_inverse = pow(client_private_key, -1, CURVE.order)

enc_m = xor_bytes(delta_hash, bigint_to_bytes(m))
m_send = bytes_to_bigint(xor_bytes(delta_hash, bigint_to_bytes(m)))


x_common = bigint_to_bytes(common_point.x(), 32)
delta_bytes = bigint_to_bytes(delta, 32)

delta_xor_commonkey = xor_bytes(delta_bytes, x_common)

m_send2, delta_xor_commonkey2 = encrypt_m(m, delta, common_point)

r_send = (r0 - (m_send - m0) * private_key_mult_inverse) % CURVE.order
r_send2 = encrypt_r(m_send, m0, r0, private_key_mult_inverse)

ch2 = (m_send + r_send * client_private_key) * CURVE.generator
server_chameleon_h = server_chameleon_hash(m_send2, r_send2, client_public_key)

crypt = ClientCrypt(server_public_key, client_private_key, m0, r0, delta)
class_ch = crypt.calc_chameleon_hash()
class_enc_m, commonkey_delta_xor = crypt.encrypt_m_int(m)
class_enc_r = crypt.encrypt_r(class_enc_m)

print("d", delta)
print("m ", m_send)
print("m2: ", m_send2)
print("class_m", class_enc_m)
print("r ", r_send)
print("r2: ", r_send2)
print("ch2", ch2.x(), ch2.y())
print("server_chameleon_h: ", server_chameleon_h.x(), server_chameleon_h.y())
print("class_ch", class_ch.x(), class_ch.y())
print("ch1: ", ch.x(), ch.y())
print("d^k", delta_xor_commonkey)
print("d^k2: ", delta_xor_commonkey2)
print("class d^k", commonkey_delta_xor)
print("---------------------------------------------")

common_point_svr = server_private_key * client_public_key
x_common_svr = bigint_to_bytes(common_point_svr.x(), 32)

delta_svr = bytes_to_bigint(xor_bytes(delta_xor_commonkey, x_common_svr))


delta_hash = sha256_int(delta_svr)
dec_m = xor_bytes(delta_hash, enc_m)

srv_crypt = ServerCrypt(client_public_key, server_private_key, class_ch)


print("ServerCrypt ch hash comparison:", srv_crypt.compare_chameleon_hash(class_ch, m_send, r_send))
print("Decrypted message: ", srv_crypt.decrypt_message(m_send, delta_xor_commonkey))

print(dec_m)

"""
message = "nagyonjoezAszagdogaaaa"
message_bytes = message.encode()

converted_message = calculate_message_format(message_bytes)

encrypted_message = m_encryption(converted_message, client_private_key, server_public_key)

print("Encrypted m__: ", encrypted_message)

encrypted_r = r_encryption(converted_message, m0, r0, client_private_key)

print("Encrypted r__: ", encrypted_r)


# Server part
print(chameleon_hash_challange(encrypted_message, encrypted_r, client_public_key, chameleon_hash))"""
