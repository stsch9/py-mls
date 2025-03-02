from src.crypto_basics import read_opaque_vec, write_opaque_vec, Credential, write_vector, read_vector, CipherSuite
from src.framing import ProtocolVersion
from typing import List


class Capabilities(object):
    def __init__(self, versions: List[ProtocolVersion], cipher_suites: List[CipherSuite]):
        self.versions = versions
        self.cipher_suites = cipher_suites

    @classmethod
    def decode(cls, data):
        versions, data = read_vector(data, lambda x: (ProtocolVersion(x[:2]), x[2:]))
        cipher_suites, data = read_vector(data, lambda x: (CipherSuite(x[:2]), x[2:]))
        return cls(versions, cipher_suites), data

    @property
    def encode(self) -> bytes:
        return (write_vector(len(self.versions), self.versions, lambda x: x.value) +
                write_vector(len(self.cipher_suites), self.cipher_suites, lambda x: x.value))


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
        capabilities, data = Capabilities.decode(data)
        return cls(encryption_key, signature_key, credential, capabilities), data

    @property
    def encode(self) -> bytes:
        s = (write_opaque_vec(self.encryption_key) + write_opaque_vec(self.signature_key) + self.credential.encode +
             self.capabilities.encode)
        return s
