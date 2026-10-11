import hashlib, json, sys

assert hashlib.blake2s(b"abc").hexdigest() == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
vs = []
for n in [0, 1, 3, 55, 63, 64, 65, 127, 128, 129, 255, 256, 1000]:
    msg = bytes((i * 7 + 3) & 0xff for i in range(n))
    vs.append({"name": f"len{n}", "key_hex": "", "msg_hex": msg.hex(), "digest_hex": hashlib.blake2s(msg).hexdigest()})
    key = bytes(range(32))
    vs.append({"name": f"keyed_len{n}", "key_hex": key.hex(), "msg_hex": msg.hex(),
               "digest_hex": hashlib.blake2s(msg, key=key).hexdigest()})
json.dump({"primitive": "blake2s_256", "source": "Python hashlib.blake2s (RFC 7693)", "vectors": vs},
          open(sys.argv[1], "w"), indent=1)
