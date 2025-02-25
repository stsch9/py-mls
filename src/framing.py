from enum import Enum
from typing import Optional
from src.crypto_basics import write_opaque_vec, read_opaque_vec

# perhaps it is better to use bytearry instead of bytes: # https://stackoverflow.com/questions/44356435/remove-first-n-elements-of-bytes-object-without-copying

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
    def __init__(self, sender_type: SenderType, leaf_index: Optional[bytes]=None, sender_index: Optional[bytes]=None):
        self.sender_type = sender_type
        if sender_type == SenderType.member:
            if not leaf_index:
                raise Exception("leaf_index required")
            else:
                self.leaf_index = leaf_index
        if sender_type == SenderType.external:
            if not sender_index:
                raise Exception("sender_type required")
            else:
                self.sender_index = sender_index

    @classmethod
    def decode(cls, data: bytes):
        sender_type = SenderType(data[:1])
        if sender_type == SenderType.member:
            leaf_index = data[1:5]
            return cls(sender_type, leaf_index=leaf_index), data[5:]
        elif sender_type == SenderType.external:
            sender_index = data[1:5]
            return cls(sender_type, sender_index=sender_index), data[5:]
        else:
            return cls(sender_type), data[1:]

    @property
    def encode(self) -> bytes:
        s = self.sender_type.value
        if self.sender_type == SenderType.member:
            s += self.leaf_index
        if self.sender_type == SenderType.external:
            s += self.sender_index
        return s


class FramedContent(object):
    def __init__(self, group_id: bytes, epoch: bytes, sender: Sender, authenticated_data: bytes,
                 content_type: ContentType, application_data: Optional[bytes]=None):
        self.group_id = group_id
        if len(epoch) == 8:
            self.epoch = epoch
        else:
            raise Exception("mls: invalid epoch")
        self.sender = sender
        self.authenticated_data = authenticated_data
        self.content_type = content_type
        if content_type == ContentType.application:
            if not application_data:
                raise Exception("application_data required")
            else:
                self.application_data = application_data


    @classmethod
    def decode(cls, data: bytes):
        group_id, data = read_opaque_vec(data)
        epoch = data[:8]
        data = data[8:]
        sender, data = Sender.decode(data)
        authenticated_data, data = read_opaque_vec(data)
        content_type = ContentType(data[:1])
        data = data[1:]
        if content_type == ContentType.application:
            application_data, data = read_opaque_vec(data)
            return cls(group_id=group_id, epoch=epoch, sender=sender, authenticated_data=authenticated_data,
                   content_type=content_type, application_data=application_data)

    @property
    def encode(self) -> bytes:
        s = (write_opaque_vec(self.group_id) + self.epoch + self.sender.encode + write_opaque_vec(self.authenticated_data)
             + self.content_type.value)
        if self.content_type == ContentType.application:
            s += write_opaque_vec(self.application_data)
        return s
