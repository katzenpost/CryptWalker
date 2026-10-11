import hashlib, hmac, json, sys

HASHES = {"SHA-256": hashlib.sha256, "SHA-512": hashlib.sha512,
          "BLAKE2b-512": hashlib.blake2b, "BLAKE2s-256": hashlib.blake2s}

rfc4231 = [
    ("tc1", b"\x0b" * 20, b"Hi There"),
    ("tc2", b"Jefe", b"what do ya want for nothing?"),
    ("tc3", b"\xaa" * 20, b"\xdd" * 50),
    ("tc4", bytes(range(1, 26)), b"\xcd" * 50),
    ("tc6", b"\xaa" * 131, b"Test Using Larger Than Block-Size Key - Hash Key First"),
    ("tc7", b"\xaa" * 131, b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."),
]
rfc5869 = [
    ("tc1", b"\x0b" * 22, bytes(range(13)), bytes(range(0xf0, 0xfa)), 42),
    ("tc2", bytes(range(0x00, 0x50)), bytes(range(0x60, 0xb0)), bytes(range(0xb0, 0x100)), 82),
    ("tc3", b"\x0b" * 22, b"", b"", 42),
    ("long", b"\x0b" * 22, b"salt", b"info", 300),
]

def hkdf(h, salt, ikm, info, n):
    prk = hmac.new(salt or b"\x00" * h().digest_size, ikm, h).digest()
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return prk, out[:n]

prk, okm = hkdf(hashlib.sha256, *rfc5869[0][2:3], rfc5869[0][1], rfc5869[0][3], 42)
assert okm.hex() == "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"

hmacs, hkdfs = [], []
for hn, h in HASHES.items():
    for name, key, msg in rfc4231:
        hmacs.append({"hash": hn, "name": name, "key_hex": key.hex(), "msg_hex": msg.hex(),
                      "tag_hex": hmac.new(key, msg, h).hexdigest()})
    for name, ikm, salt, info, n in rfc5869:
        prk, okm = hkdf(h, salt, ikm, info, n)
        hkdfs.append({"hash": hn, "name": name, "ikm_hex": ikm.hex(), "salt_hex": salt.hex(),
                      "info_hex": info.hex(), "length": n, "prk_hex": prk.hex(), "okm_hex": okm.hex()})

json.dump({"primitive": "hmac_hkdf",
           "source": "RFC 4231 and RFC 5869 inputs; outputs from Python hashlib/hmac",
           "hmac": hmacs, "hkdf": hkdfs}, open(sys.argv[1], "w"), indent=1)
