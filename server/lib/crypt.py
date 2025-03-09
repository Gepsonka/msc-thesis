import ecdsa

CURVE = ecdsa.SECP256k1

def create_key():
  private_key = ecdsa.SigningKey.generate(curve=CURVE)
  public_key = private_key.get_verifying_key()


  return private_key, public_key


def read_keys_from_hex(private_key_text):
  private_key_bytes = bytes.fromhex(private_key_text)
  private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=CURVE)

  public_key = private_key.get_verifying_key()

  return private_key, public_key


