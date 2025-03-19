import ecdsa
import hashlib
import time
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import ecdsa.ellipticcurve
from typing import Tuple


CURVE = ecdsa.SECP256k1


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


def generate_keys() -> Tuple[int, ecdsa.ellipticcurve.PointJacobi]:
    private_key = ecdsa.SigningKey.generate(curve=CURVE)
    public_key = private_key.get_verifying_key()

    return private_key.privkey.secret_multiplier, public_key.pubkey.point


def read_keys_from_hex(private_key_text):
    private_key_bytes = bytes.fromhex(private_key_text)
    private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=CURVE)

    public_key: ecdsa.VerifyingKey = private_key.get_verifying_key()

    return private_key, public_key


def calculate_chameleon_hash(
    m0: int, r0: int, x: int
) -> ecdsa.ellipticcurve.PointJacobi:
    """
    Calculates chameleon hash from the given parameters

    Parameters:
    m0: 256 bit random number
    r0: 256 bi random number
    x: private key

    Returns:
    Chameleon hash
    """
    point = (m0 + r0 * x) * CURVE.generator
    return point


def calculate_message_format(m: bytes):
    """
    Parameters:
    m: message in utf-8 string format

    Returns:
    Message int in the format: m || timestamp || H(m || timestamp)
    """
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


def encrypt_r(m: int, m0: int, r0: int, private_key_mult_inverse: int):
    """
    Creates r__ in the protocol

    Parameters:
    converted_message (str): The message created by calculate_message_format method
    m0 (int): Random 256 bit integer generated at the beginning of the protocol.
    r0 (int): Ransom 256 bit integer generated at the beggining of the protocol.
    client_private_key (ecdsa.SigningKey): Private key (x) of the client

    Returns:
    bytes: Encrypted r
    """

    return (r0 - (m - m0) * private_key_mult_inverse) % CURVE.order


def server_chameleon_hash(
    m_send: int, r_send: int, client_public_key: ecdsa.ellipticcurve.PointJacobi
):
    return (m_send * CURVE.generator) + (r_send * client_public_key)


def chameleon_hash_challange(
    client_chameleon_hash: ecdsa.ellipticcurve.PointJacobi,
    server_chameleon_hash: ecdsa.ellipticcurve.PointJacobi,
) -> bool:
    return (
        client_chameleon_hash.x() == server_chameleon_hash.x()
        and client_chameleon_hash.y() == server_chameleon_hash.y()
    )


def srv_common_point(
    server_private_key: int, client_public_key: ecdsa.ellipticcurve.PointJacobi
):
    return server_private_key * client_public_key


def srv_delta(
    delta_xor_commonkey: bytes, common_point: ecdsa.ellipticcurve.PointJacobi
):
    x_common_bytes = bigint_to_bytes(common_point.x(), 32)
    srv_delta = bytes_to_bigint(xor_bytes(delta_xor_commonkey, x_common_bytes))

    delta_hash = sha256_int(srv_delta)

    return delta_hash


def decrypt_m(m_send, delta_hash):
    return xor_bytes(delta_hash, m_send)


class ClientCrypt:
    CURVE = ecdsa.SECP256k1
    KEY_SIZE = 256

    def __init__(
        self,
        srv_public_key: ecdsa.ellipticcurve.PointJacobi,
        client_private_key: int | None,
        m0: int | None = None,
        r0: int | None = None,
        delta: int | None = None,
    ):
        self._srv_public_key = srv_public_key
        if client_private_key is None:
            self._client_private_key, self._client_public_key = generate_keys()
        else:
            self._client_private_key = client_private_key
            self._client_public_key = client_private_key * self.CURVE.generator

        self._common_key = self._srv_public_key * self._client_private_key

        if m0 is None:
            self._m0 = random.getrandbits(self.KEY_SIZE)
        else:
            self._m0 = m0

        if r0 is None:
            self._r0 = random.getrandbits(self.KEY_SIZE)
        else:
            self._r0 = r0

        if delta is None:
            self._delta = random.getrandbits(self.KEY_SIZE)
        else:
            self._delta = delta

        self._delta_hash = sha256_int(self._delta)

    def calc_chameleon_hash(self) -> ecdsa.ellipticcurve.PointJacobi:
        """Calculates chameleon hash"""
        return (self._m0 + self._r0 * self._client_private_key) * CURVE.generator

    def encrypt_m_int(self, m: int):
        m_send = bytes_to_bigint(xor_bytes(self._delta_hash, bigint_to_bytes(m)))

        return m_send, self._delta_xor_commonkey()

    def encrypt_r(self, m_send: int):
        return (
            self._r0
            - (m_send - self._m0) * self._private_key_mult_inverse() % self.CURVE.order
        )

    def _delta_xor_commonkey(self):
        delta_bytes = bigint_to_bytes(self._delta, 32)
        commonkey_x_bytes = bigint_to_bytes(self._common_key.x(), 32)
        return xor_bytes(delta_bytes, commonkey_x_bytes)

    def _private_key_mult_inverse(self):
        return pow(self._client_private_key, -1, self.CURVE.order)


class ServerCrypt:
    CURVE = ecdsa.SECP256k1
    KEY_SIZE = 256

    def __init__(
        self,
        client_public_key: ecdsa.ellipticcurve.PointJacobi,
        server_private_key: int,
        client_chameleon_hash: ecdsa.ellipticcurve.PointJacobi
    ):
        self._client_public_key = client_public_key
        self._server_private_key = server_private_key
        self._server_public_key: ecdsa.ellipticcurve.PointJacobi = (
            self._server_private_key * self.CURVE.generator
        )

        self._common_point = self._client_public_key * self._server_private_key

        self._client_chameleon_hash = client_chameleon_hash

    def set_delta_xor_commonkey(self, delta_xor_commonkey: bytes):
        self._delta_xor_commonkey = delta_xor_commonkey

    def compare_chameleon_hash(
        self, client_chameleon_hash: ecdsa.ellipticcurve.PointJacobi, m_send: int, r_send: int
    ) -> bool:
        srv_ch_hash = self._calc_chameleon_hash(m_send, r_send)
        return srv_ch_hash.x() == client_chameleon_hash.x() and srv_ch_hash.y() == client_chameleon_hash.y()

    def decrypt_message(self, m_send: int, delta_xor_commonkey: int):
        delta_hash = self._calc_delta_hash(delta_xor_commonkey)
        m_send_bytes = bigint_to_bytes(m_send)

        return xor_bytes(delta_hash, m_send_bytes)

    def _calc_delta_hash(self, delta_xor_commonkey: bytes):
        x_common_bytes = bigint_to_bytes(self._common_point.x(), 32)
        srv_delta = bytes_to_bigint(xor_bytes(delta_xor_commonkey, x_common_bytes))

        delta_hash = sha256_int(srv_delta)

        return delta_hash

    def _calc_chameleon_hash(
        self, m_send: int, r_send: int
    ) -> ecdsa.ellipticcurve.PointJacobi:
        return m_send * self.CURVE.generator + r_send * self._client_public_key

    