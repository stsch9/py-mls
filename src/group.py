from src.key_package import KeyPackage
from src.types import ProposalType


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