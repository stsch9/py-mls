from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey, X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey


def write_varint(n: int) -> bytes:
    if n < (1 << 6):
        return n.to_bytes(1, byteorder='big')
    elif n < (1 << 14):
        return ((0b01 << 14) | n).to_bytes(2, byteorder='big')
    elif n < (1 << 30):
        # Wenn n kleiner als 1073741824 ist, füge es als 4 Bytes hinzu mit einem 10 Präfix
        return ((0b10 << 30) | n).to_bytes(4, byteorder='big')
    else:
        # Wenn n größer als 30 Bits ist, setze einen Fehler
        raise Exception("mls: varint exceeds 30 bits")

def read_varint(data: bytes) -> tuple[int, int]:
    # The length of variable-length integers is encoded in the
    # first two bits of the first byte.
    v = data[:1]
    prefix = int.from_bytes(v) >> 6
    if prefix == 3:
        raise Exception('invalid variable length integer prefix')

    length = 1 << prefix

    # Once the length is known, remove these bits and read any
    # remaining bytes.
    v = int.from_bytes(v) & 0x3f

    for i in range(1,length):
        v = (v << 8) + int.from_bytes(data[i:i+1])

    # Check if the value would fit in half the provided length.
    if prefix >= 1 and v < (1 << int(8*(length/2) - 2)):
        raise Exception('minimum encoding was not used')

    return v, length


def write_opaque_vec(value: bytes) -> bytes:
    if len(value) >= 1<<32:
        raise Exception("mls: opaque size exceeds maximum value of uint32")

    return write_varint(len(value)) + value


def read_opaque_vec(value: bytes) -> tuple[bytes, bytes]:
    v, l = read_varint(value)
    if len(value[l:]) < v:
        raise Exception("mls: cannot read opaque vec")
    return value[l:v+l], value[v+l:]

def marshal_sign_content(label: bytes, content: bytes) -> bytes:
    label = b'MLS 1.0 ' + label
    return write_opaque_vec(label) + write_opaque_vec(content)

def marshal_encrypt_context(label: bytes, content: bytes) -> bytes:
    label = b'MLS 1.0 ' + label
    return write_opaque_vec(label) + write_opaque_vec(content)

def SignWithLabel(SignatureKey: bytes, Label: bytes, Content: bytes) -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(SignatureKey)

    return private_key.sign(marshal_sign_content(Label, Content))

def VerifyWithLabel(VerificationKey: bytes, Label: bytes, Content: bytes, SignatureValue: bytes) -> None:
    public_key = Ed25519PublicKey.from_public_bytes(VerificationKey)

    return public_key.verify(SignatureValue, marshal_sign_content(Label, Content))

def EncryptWithLabel(PublicKey: bytes, Label: bytes, Context: bytes, Plaintext: bytes) -> tuple[bytes, bytes]:
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
    pkr = KEMKey.from_pyca_cryptography_key(X25519PublicKey.from_public_bytes(PublicKey))
    enc, sender = suite.create_sender_context(pkr=pkr, info=marshal_encrypt_context(Label, Context))
    ct = sender.seal(Plaintext)

    return enc, ct

def DecryptWithLabel(PrivateKey: bytes, Label: bytes, Context: bytes, KEMOutput: bytes, Ciphertext: bytes) -> bytes:
    suite = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305)
    skr = KEMKey.from_pyca_cryptography_key(X25519PrivateKey.from_private_bytes(PrivateKey))
    recipient = suite.create_recipient_context(enc=KEMOutput, skr=skr, info=marshal_encrypt_context(Label, Context))

    return recipient.open(Ciphertext)

def ExpandWithLabel(Secret: bytes, Label: bytes, Context: bytes, Length: int):
    KDFLabel = Length.to_bytes(2, byteorder='big') + write_opaque_vec(b'MLS 1.0 ' + Label) + write_opaque_vec(Context)
    hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=Length, info=KDFLabel)

    return hkdf.derive(Secret)

def DeriveSecret(Secret: bytes, Label: bytes) -> bytes:
    return ExpandWithLabel(Secret, Label, b'', hashes.SHA256.digest_size)

def DeriveTreeSecret(Secret: bytes, Label: bytes, Generation: int, Length: int) -> bytes:
    return ExpandWithLabel(Secret, Label, Generation.to_bytes(4, byteorder='big'), Length)

def RefHash(label: bytes, value: bytes) -> bytes:
    RefHashInput = write_opaque_vec(label) + write_opaque_vec(value)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(RefHashInput)
    return digest.finalize()