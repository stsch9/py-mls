from src.crypto_basics import read_opaque_vec, write_opaque_vec, Credential, write_vector, read_vector, CipherSuite, CredentialType
from src.framing import ProtocolVersion
from src.types import ProposalType
from typing import List, Optional
from enum import Enum


class ExtensionType(Enum):
    application_id = bytes.fromhex("0001")
    ratchet_tree = bytes.fromhex("0002")
    required_capabilities = bytes.fromhex("0003")
    external_pub = bytes.fromhex("0004")
    external_senders = bytes.fromhex("0005")


class Capabilities(object):
    def __init__(self, versions: List[ProtocolVersion], cipher_suites: List[CipherSuite], extensions: List[ExtensionType],
                 proposals: List[ProposalType], credentials: List[CredentialType]):
        self.versions = versions
        self.cipher_suites = cipher_suites
        self.extensions = extensions
        self.proposals = proposals
        self.credentials = credentials

    @classmethod
    def decode(cls, data):
        versions, data = read_vector(data, lambda x: (ProtocolVersion(x[:2]), x[2:]))
        cipher_suites, data = read_vector(data, lambda x: (CipherSuite(x[:2]), x[2:]))
        extensions, data = read_vector(data, lambda x: (ExtensionType(x[:2]), x[2:]))
        proposals, data = read_vector(data, lambda x: (ProposalType(x[:2]), x[2:]))
        credentials, data = read_vector(data, lambda x: (CredentialType(x[:2]), x[2:]))
        return cls(versions, cipher_suites, extensions, proposals, credentials), data

    @property
    def encode(self) -> bytes:
        return (write_vector(len(self.versions), self.versions, lambda x: x.value) +
                write_vector(len(self.cipher_suites), self.cipher_suites, lambda x: x.value) +
                write_vector(len(self.extensions), self.extensions, lambda x: x.value) +
                write_vector(len(self.proposals), self.proposals, lambda x: x.value) +
                write_vector(len(self.credentials), self.credentials, lambda x: x.value))


class LeafNodeSource(Enum):
    key_package = int(1).to_bytes(1, byteorder='big')
    update = int(2).to_bytes(1, byteorder='big')
    commit = int(3).to_bytes(1, byteorder='big')


class Lifetime(object):
    def __init__(self, not_before: bytes, not_after: bytes):
        if len(not_before) == 8:
            self.not_before = not_before
        else:
            raise Exception("mls: invalid not_before")
        if len(not_after) == 8:
            self.not_after = not_after
        else:
            raise Exception("mls: invalid not_after")

    @classmethod
    def decode(cls, data):
        not_before = data[:8]
        data = data[8:]
        not_after = data[:8]
        data = data[8:]

        return cls(not_before=not_before, not_after=not_after), data

    @property
    def encode(self):
        return self.not_before + self.not_after


class LeafNode(object):
    def __init__(self, encryption_key: bytes, signature_key: bytes, credential: Credential, capabilities: Capabilities,
                 leaf_node_source: LeafNodeSource, extensions: List[ExtensionType], lifetime: Optional[Lifetime] = None, parent_hash: Optional[bytes] = None):
        self.encryption_key = encryption_key
        self.signature_key = signature_key
        self.credential = credential
        self.capabilities = capabilities
        self.leaf_node_source = leaf_node_source
        if leaf_node_source == LeafNodeSource.key_package:
            if not lifetime:
                raise Exception("lifetime required")
            else:
                self.lifetime = lifetime
        if leaf_node_source == LeafNodeSource.commit:
            if not parent_hash:
                raise Exception("parent_hash required")
            else:
                self.parent_hash = parent_hash
        self.extensions = extensions


    @classmethod
    def decode(cls, data):
        encryption_key, data = read_opaque_vec(data)
        signature_key, data = read_opaque_vec(data)
        credential, data = Credential.decode(data)
        capabilities, data = Capabilities.decode(data)
        leaf_node_source = LeafNodeSource(data[:1])
        data = data[1:]
        if leaf_node_source == LeafNodeSource.key_package:
            lifetime, data = Lifetime.decode(data)
            parent_hash = None
        elif leaf_node_source == LeafNodeSource.commit:
            parent_hash, data = read_opaque_vec(data)
            lifetime = None
        else:
            parent_hash = None
            lifetime = None
        credentials, data = read_vector(data, lambda x: (CredentialType(x[:2]), x[2:]))

        return cls(encryption_key, signature_key, credential, capabilities, leaf_node_source, credentials,
                    lifetime=lifetime, parent_hash=parent_hash), data

    @property
    def encode(self) -> bytes:
        s = (write_opaque_vec(self.encryption_key) + write_opaque_vec(self.signature_key) + self.credential.encode +
             self.capabilities.encode + self.leaf_node_source.value)
        if self.leaf_node_source == LeafNodeSource.key_package:
            s += self.lifetime.encode
        if self.leaf_node_source == LeafNodeSource.commit:
            s += write_opaque_vec(self.parent_hash)
        s += write_vector(len(self.extensions), self.extensions, lambda x: x.value)
        return s


class LeafNodeTBS(object):
    def __init__(self):
        pass