from enum import Enum
from key_package import KeyPackage


class ProposalType(Enum):
    add = bytes.fromhex("0001")
    update = bytes.fromhex("0002")
    remove = bytes.fromhex("0003")
    psk = bytes.fromhex("0004")
    reinit = bytes.fromhex("0005")
    external_init = bytes.fromhex("0006")
    group_context_extensions = bytes.fromhex("0007")


class Proposal(object):
    def __init__(self, proposal_type: ProposalType):
        self.proposal_type = proposal_type

    @classmethod
    def decode(cls, data: bytes):
        proposal_type = ProposalType(data[:2])
        data = data[2:]
        return cls(proposal_type), data

    @property
    def encode(self) -> bytes:
        s = self.proposal_type.value
        return s


class Add(object):
    def __init__(self, key_package: KeyPackage):
        self.key_package = key_package

    @classmethod
    def decode(cls, data: bytes):
        pass

    @property
    def encode(self) -> bytes:
        s = self.key_package.encode
        return s