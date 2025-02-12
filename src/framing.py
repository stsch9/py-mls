from enum import Enum, member


class ProtocolVersion(Enum):
    mls10 = int(1).to_bytes(2, byteorder='big')


class ContentType(Enum):
    application = int(1).to_bytes(1, byteorder='big')
    proposal = int(2).to_bytes(1, byteorder='big')
    commit = int(3).to_bytes(1, byteorder='big')


class SenderType(Enum):
    member = int(1).to_bytes(1, byteorder='big')
    external = int(2).to_bytes(1, byteorder='big')
    new_member_proposal = int(3).to_bytes(1, byteorder='big')
    new_member_commit = int(4).to_bytes(1, byteorder='big')


class Sender(object):
    def __init__(self, sender_type: SenderType, leaf_index = b'\x00' * 4, sender_index = b'\x00' * 4):
        self.sender_type = sender_type
        if sender_type == SenderType.member:
            self.leaf_index = leaf_index
        if sender_type == SenderType.external:
            self.sender_index = sender_index

    @classmethod
    def decode(cls, data: bytes):
        sender_type = SenderType(data[:1])
        if sender_type == SenderType.member:
            leaf_index = data[1:5]
            return cls(sender_type, leaf_index=leaf_index)
        elif sender_type == SenderType.external:
            sender_index = data[1:5]
            return cls(sender_type, sender_index=sender_index)
        else:
            return cls(sender_type)

    @property
    def encode(self) -> bytes:
        s = self.sender_type.value
        if self.sender_type == SenderType.member:
            s += self.leaf_index
        if self.sender_type == SenderType.external:
            s += self.sender_index
        return s
