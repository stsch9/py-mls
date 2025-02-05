import unittest
from src.crypto_basics import SignWithLabel, VerifyWithLabel, EncryptWithLabel, DecryptWithLabel, DeriveSecret, ExpandWithLabel
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class TestCryptoBasics(unittest.TestCase):
    def test_derive_secret(self):
        label = b"DeriveSecret"
        out = "aad859818ca5f2a9896d4d3ee2dccc0cefcd69b666bdb16b52f1de15fb1a5567"
        secret = "cae460c779ebaa3e81c061a371486dff1ed1ff273bea369cc0fc46550b83c407"

        self.assertEqual(DeriveSecret(bytes.fromhex(secret), label), bytes.fromhex(out))

    def test_encrypt_with_label(self):
        ciphertext = "40dd09ad4c5dc29d373f814bf054c9359cb75a468bc4d2c8bbcffb072a73105c4d9416ebd4fafeb62e59a9dea55da3cd"
        context = "0d6a5cf9ee88b1f8c79d8512477d9bfc5496c207c8173f8dcac0368b4dba7407"
        kem_output = "f26e9e5a94396a90f85a5f72eedf3dacfb1b7f4164e0573edeb9c6c912e1cb49"
        label = b"EncryptWithLabel"
        plaintext = "1dd4c1904996ce7d42cee7de68881459fa7a345da59a02040ade37103505baf6"
        priv = "9d122ad4638fcb301b6eb5f4073414afb44bb34d37b4ddee9975b2941d700edb"
        pub = "7a5544b59f5940bf093c921469a00a170a7c92ba56c173d74db32713608d8a40"

        sk = X25519PrivateKey.from_private_bytes(bytes.fromhex(priv))
        self.assertEqual(sk.public_key().public_bytes_raw(), bytes.fromhex(pub))

        enc, ct = EncryptWithLabel(bytes.fromhex(pub), label, bytes.fromhex(context), bytes.fromhex(plaintext))
        self.assertEqual(DecryptWithLabel(bytes.fromhex(priv), label, bytes.fromhex(context), enc, ct),
                         bytes.fromhex(plaintext))

        self.assertEqual(DecryptWithLabel(bytes.fromhex(priv), label, bytes.fromhex(context), bytes.fromhex(kem_output),
                                          bytes.fromhex(ciphertext)), bytes.fromhex(plaintext))

    def test_expand_with_label(self):
        context = "2e07148f4340c62a55e7608c20d73fddf1f3b8dafb2c7ef24eceb70e136c0d8c"
        label = b"ExpandWithLabel"
        length = 32
        out = "1df5ba7996a34f75d717916a094a14083c03a75e80f0330a8095f5f11cfe1e1f"
        secret = "55aa3ae5242564782567ce097beafe19510230660008b2cc064a78387fa16f36"

        self.assertEqual(ExpandWithLabel(bytes.fromhex(secret), label, bytes.fromhex(context), length), bytes.fromhex(out))

    def test_sign_with_label(self):
        content = "df308cf2dbf471edf2c29d30e3daf161b5b87d350ee3b2c715c298ec3d10d432"
        label = b"SignWithLabel"
        priv = "4e312160ee4981358db479aa877412847abc7f7054b5605511256c395404d054"
        pub = "18275f892ee0ca6f4687ff26c990776387502646ff658c3f572b324faecb05c5"
        signature = "4f56851c2c47f5115a61ff0ab6121b4a4732d4e94805fc7135a5132f87d5ca5f1dc7408816c1ea4f25887725cf5914b48c427a52cabcfeb746a2b8a12e821f08"
        private_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv))
        self.assertEqual(private_key.public_key().public_bytes_raw(), bytes.fromhex(pub))
        self.assertEqual(SignWithLabel(bytes.fromhex(priv), label, bytes.fromhex(content)), bytes.fromhex(signature))

    def test_verify_with_label(self):
        content = "df308cf2dbf471edf2c29d30e3daf161b5b87d350ee3b2c715c298ec3d10d432"
        label = b"SignWithLabel"
        priv = "4e312160ee4981358db479aa877412847abc7f7054b5605511256c395404d054"
        pub = "18275f892ee0ca6f4687ff26c990776387502646ff658c3f572b324faecb05c5"
        signature = "4f56851c2c47f5115a61ff0ab6121b4a4732d4e94805fc7135a5132f87d5ca5f1dc7408816c1ea4f25887725cf5914b48c427a52cabcfeb746a2b8a12e821f08"
        VerifyWithLabel(bytes.fromhex(pub), label, bytes.fromhex(content), bytes.fromhex(signature))
