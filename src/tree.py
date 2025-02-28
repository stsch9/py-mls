from src.crypto_basics import read_opaque_vec, write_opaque_vec, Credential, write_vector
from src.framing import ProtocolVersion
from typing import List


class Capabilities(object):
    def __init__(self, versions: List[ProtocolVersion]):
        self.versions = versions

    @classmethod
    def decode(cls, data):
        pass

    @property
    def encode(self) -> bytes:
        return write_vector(len(self.versions), self.versions, lambda x: x.value)



class LeafNode(object):
    def __init__(self, encryption_key: bytes, signature_key: bytes, credential: Credential, capabilities: Capabilities):
        self.encryption_key = encryption_key
        self.signature_key = signature_key
        self.credential = credential
        self.capabilities = capabilities

    @classmethod
    def decode(cls, data):
        encryption_key, data = read_opaque_vec(data)
        signature_key, data = read_opaque_vec(data)
        credential, data = Credential.decode(data)
        return cls(encryption_key, signature_key, credential), data

    @property
    def encode(self) -> bytes:
        s = write_opaque_vec(self.encryption_key) + write_opaque_vec(self.signature_key) + self.credential.encode
        return s
