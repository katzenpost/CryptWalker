import json, sys

src, out, key_bits = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = json.load(open(src))
vs = [{"tcId": t["tcId"], "key_hex": t["key"], "nonce_hex": t["iv"], "ad_hex": t["aad"],
       "pt_hex": t["msg"], "ct_hex": t["ct"], "tag_hex": t["tag"], "valid": t["result"] == "valid"}
      for g in d["testGroups"] if g["keySize"] == key_bits and g["ivSize"] == 96 and g["tagSize"] == 128
      for t in g["tests"]]
json.dump({"source": "Wycheproof " + src.split("/")[-1] + " (96-bit nonce, 128-bit tag, %d-bit key)" % key_bits,
           "vectors": vs}, open(out, "w"), indent=1)
print(out, len(vs))
