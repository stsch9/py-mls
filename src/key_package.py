from src.framing import ProtocolVersion
from src.crypto_basics import CipherSuite, read_opaque_vec, write_opaque_vec
from src.tree import LeafNode


class KeyPackage(object):
    def __init__(self, version: ProtocolVersion, cipher_suite: CipherSuite, init_key: bytes, leaf_node: LeafNode):
        self.version = version
        self.cipher_suite = cipher_suite
        self.init_key = init_key
        self.leaf_node = leaf_node

    @classmethod
    def decode(cls, data: bytes):
        version = ProtocolVersion(data[:2])
        data = data[2:]
        cipher_suite = CipherSuite(data[:2])
        data = data[2:]
        init_key, data = read_opaque_vec(data)
        leaf_node, data = LeafNode.decode(data)
        return cls(version, cipher_suite, init_key, leaf_node), data

    @property
    def encode(self) -> bytes:
        s = self.version.value + self.cipher_suite.value + write_opaque_vec(self.init_key) + self.leaf_node.encode
        return s
