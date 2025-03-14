import ecdsa
import hashlib
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import ecdsa.ellipticcurve


CURVE = ecdsa.SECP256k1

def string_to_bigint(s):
    byte_array = s.encode('utf-8')  
    big_int = int.from_bytes(byte_array, byteorder='big')
    return big_int

def bigint_to_string(n):
    byte_array = n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')
    return byte_array.decode('utf-8')


def bytes_to_bigint(b):
    return int.from_bytes(b, byteorder='big')

def bigint_to_bytes(n, length = 64):
    return n.to_bytes(length, byteorder='big')

def sha256_int(n):
    return hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).digest()
def xor_bytes(bytes1, bytes2):
    if len(bytes1) > len(bytes2):
        return bytes(bytes1[i] ^ bytes2[i % len(bytes2)] for i in range(len(bytes1)))
    if len(bytes2) > len(bytes1):
        return bytes(bytes2[i] ^ bytes1[i % len(bytes1)] for i in range(len(bytes2)))
    return bytes(a ^ b for a, b in zip(bytes1, bytes2))
    
def generate_keys():
  private_key = ecdsa.SigningKey.generate(curve=CURVE)
  public_key= private_key.get_verifying_key()

  return private_key.privkey.secret_multiplier, public_key.pubkey.point





def read_keys_from_hex(private_key_text):
  private_key_bytes = bytes.fromhex(private_key_text)
  private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=CURVE)

  public_key: ecdsa.VerifyingKey = private_key.get_verifying_key()

  return private_key, public_key



def calculate_chameleon_hash(m0: int, r0: int, x: int) -> ecdsa.ellipticcurve.PointJacobi:
  '''
  Calculates chameleon hash from the given parameters

  Parameters:
  m0: 256 bit random number
  r0: 256 bi random number
  x: private key

  Returns:
  Chameleon hash
  '''
  point = (m0 + r0 * x) * CURVE.generator
  return point


def calculate_message_format(m: bytes):
  '''
  Parameters:
  m: message in utf-8 string format

  Returns:
  Message int in the format: m || timestamp || H(m || timestamp)
  '''
  timestamp_bytes = str(int(time.time())).encode()

  timestamp_message_hash = hashlib.sha256(m + timestamp_bytes).digest()

  return m + timestamp_bytes + timestamp_message_hash

def encrypt_m(m: int, delta: int, common_point: ecdsa.ellipticcurve.PointJacobi): 
  delta_hash = sha256_int(delta)

  m_send = bytes_to_bigint(xor_bytes(delta_hash, bigint_to_bytes(m)))

  x_common = bigint_to_bytes(common_point.x(), 32)
  delta_bytes = bigint_to_bytes(delta, 32)

  delta_xor_commonkey = xor_bytes(delta_bytes, x_common)

  return m_send, delta_xor_commonkey

def encrypt_r(m: int, m0: int, r0: int, client_private_key: int, private_key_mult_inverse: int):
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

  return (r0 - (m-m0) * private_key_mult_inverse) % CURVE.order


def chameleon_hash_challange(m__: bytes, r__: bytes, client_public_key: ecdsa.VerifyingKey, chameleon_hash: ecdsa.ellipticcurve.PointJacobi) -> bool:
  m__int = int.from_bytes(m__, 'big')
  r__int = int.from_bytes(r__, 'big', signed=True)

  challange_result_point = m__int * CURVE.generator + r__int * client_public_key.pubkey.point

  print("m__int: ", m__int)
  print("r__int: ", r__int)
  print("challange_result_point.x(): ", challange_result_point.x())
  print("challange_result_point.y(): ", challange_result_point.y())


  return challange_result_point.x() == chameleon_hash.x() and challange_result_point.y() == chameleon_hash.y()



