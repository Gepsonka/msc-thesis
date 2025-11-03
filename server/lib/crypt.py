import hashlib
from typing import Tuple
import ecdsa

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
    private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
    public_key = private_key.get_verifying_key()

    return private_key.privkey.secret_multiplier, public_key.pubkey.point


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