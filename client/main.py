import random
from lib.crypt import *


client_private_key, client_public_key = generate_keys()
server_private_key, server_public_key = generate_keys()


m0 = random.getrandbits(256)
r0 = random.getrandbits(256)

# Client
chameleon_hash = calculate_chameleon_hash(m0, r0, client_private_key)

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