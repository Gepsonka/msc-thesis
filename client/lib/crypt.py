import ecdsa
import hashlib
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import ecdsa.ellipticcurve


CURVE = ecdsa.SECP256k1

def generate_keys():
  private_key = ecdsa.SigningKey.generate(curve=CURVE)
  public_key: ecdsa.VerifyingKey = private_key.get_verifying_key()


  return private_key, public_key


def read_keys_from_hex(private_key_text):
  private_key_bytes = bytes.fromhex(private_key_text)
  private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=CURVE)

  public_key: ecdsa.VerifyingKey = private_key.get_verifying_key()

  return private_key, public_key



def calculate_chameleon_hash(m0, r0, x: ecdsa.SigningKey):
  '''
  Calculates chameleon hash from the given parameters

  Parameters:
  m0: 256 bit random number
  r0: 256 bi random number
  x: private key
  G: generator element

  Returns:
  Chameleon hash
  '''
  privkey_int = int.from_bytes(x.to_string(), "big")
  point = (m0 + r0 * privkey_int) * CURVE.generator
  return point


def calculate_message_format(m: bytes):
  '''
  Parameters:
  m: message in utf-8 string format

  Returns:
  Message bytes in the format: m || timestamp || H(m || timestamp)
  '''
  timestamp_byte_length = (int(time.time()).bit_length() + 7) // 8 or 1
  timestamp_bytes = int(time.time()).to_bytes(timestamp_byte_length, 'big')

  timestamp_message_hash = hashlib.sha256(m + timestamp_bytes).digest()

  return m + timestamp_bytes + timestamp_message_hash

def m_encryption(m_: bytes, client_private_key: ecdsa.SigningKey, server_public_key: ecdsa.VerifyingKey):
  '''
  Parameters:
  m_: message in the format returner by calculate_message_format
  private_key: Client private key
  server_public_key: Public key from the server

  Returns:
  Encrypted message
  '''
  random_delta = random.getrandbits(256)
  random_delta_bytes = random_delta.to_bytes(32, 'big')
  hashed_delta_bytes = hashlib.sha256(random_delta_bytes).digest()

  message_bytes = m_

  cipher = AES.new(hashed_delta_bytes, AES.MODE_ECB)
  padded_data = pad(message_bytes, AES.block_size)
  ciphertext = cipher.encrypt(padded_data)

  common_public_key = server_public_key.pubkey.point * client_private_key.privkey.secret_multiplier
  common_public_key_x_bytes = common_public_key.x().to_bytes(32, 'big')
  common_public_key_delta_xor = bytes(a ^ b for a, b in zip(random_delta_bytes, common_public_key_x_bytes))

  return ciphertext + common_public_key_delta_xor
  
def r_encryption(converted_message: bytes, m0: int, r0: int, client_private_key: ecdsa.SigningKey):
  '''
  Creates r__ in the protocol

  Parameters:
  converted_message (str): The message created by calculate_message_format method
  m0 (int): Random 256 bit integer generated at the beginning of the protocol.
  r0 (int): Ransom 256 bit integer generated at the beggining of the protocol.
  client_private_key (ecdsa.SigningKey): Private key (x) of the client 
  
  Returns:
  bytes: Encrypted r
  '''
  converted_message_int = int.from_bytes(converted_message, 'big')

  m_minus_m0 = converted_message_int - m0

  private_key_mult_inverse = pow(client_private_key.privkey.secret_multiplier, -1, CURVE.order)

  r__ = r0 - m_minus_m0 * private_key_mult_inverse

  r__byte_length = (r__.bit_length() + 7) // 8 or 1 
  r__bytes = byte_data = r__.to_bytes(r__byte_length, byteorder='big', signed=True)

  return r__bytes


def chameleon_hash_challange(m__: bytes, r__: bytes, client_public_key: ecdsa.VerifyingKey, chameleon_hash: ecdsa.ellipticcurve.PointJacobi) -> bool:
  m__int = int.from_bytes(m__, 'big')
  r__int = int.from_bytes(r__, 'big', signed=True)

  challange_result_point = m__int * CURVE.generator + r__int * client_public_key.pubkey.point

  return challange_result_point.x() == chameleon_hash.x() and challange_result_point.y() == chameleon_hash.y()

