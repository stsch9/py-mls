from enum import Enum


class ProposalType(Enum):
    add = bytes.fromhex("0001")
    update = bytes.fromhex("0002")
    remove = bytes.fromhex("0003")
    psk = bytes.fromhex("0004")
    reinit = bytes.fromhex("0005")
    external_init = bytes.fromhex("0006")
    group_context_extensions = bytes.fromhex("0007")