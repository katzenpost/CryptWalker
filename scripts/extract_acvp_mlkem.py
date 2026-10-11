"""Extract one ML-KEM parameter set from NIST ACVP-Server's internalProjection.json files
(gen-val/json-files/ML-KEM-{keyGen,encapDecap}-FIPS203) into testdata/mlkem<N>_*.json."""
import json, sys

keygen_src, encdec_src, n, outdir = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
ps = f"ML-KEM-{n}"
src = "NIST ACVP-Server (github.com/usnistgov/ACVP-Server), gen-val/json-files/"

def write(name, generator, desc, vectors):
    doc = {"format_version": 1, "generator": generator, "primitive": f"mlkem{n}_{name}",
           "description": desc, "vectors": vectors}
    with open(f"{outdir}/mlkem{n}_{name}.json", "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")

kg = json.load(open(keygen_src))
write("keygen", src + f"ML-KEM-keyGen-FIPS203/internalProjection.json, {ps} test group only",
      f"Official NIST ACVP known-answer vectors for {ps} key generation (FIPS 203 Algorithm 19): d, z -> ek, dk.",
      [{"name": f"tc{t['tcId']}", "d_hex": t["d"], "z_hex": t["z"], "ek_hex": t["ek"], "dk_hex": t["dk"]}
       for g in kg["testGroups"] if g["parameterSet"] == ps for t in g["tests"]])

ed = json.load(open(encdec_src))
vs = []
for g in ed["testGroups"]:
    if g["parameterSet"] != ps: continue
    for t in g["tests"]:
        if g["function"] == "encapsulation":
            vs.append({"name": f"tc{t['tcId']}-encap", "mode": "encap", "ek_hex": t["ek"], "m_hex": t["m"],
                       "c_hex": t["c"], "k_hex": t["k"]})
        elif g["function"] == "decapsulation":
            vs.append({"name": f"tc{t['tcId']}-decap-{t['reason'].replace(' ', '_')}", "mode": "decap",
                       "dk_hex": t["dk"], "c_hex": t["c"], "k_hex": t["k"], "reason": t["reason"]})
write("encapdecap", src + f"ML-KEM-encapDecap-FIPS203/internalProjection.json, {ps} test group only",
      f"Official NIST ACVP known-answer vectors for {ps} encapsulation (FIPS 203 Algorithm 20, AFT: ek, m -> c, k) and decapsulation (Algorithm 21, VAL: dk, c -> k). The decapsulation vectors include 'modified ciphertext' cases, which exercise the implicit-rejection path (a malformed ciphertext still decapsulates to *some* pseudorandom key, deterministically, rather than erroring).",
      vs)

vs = []
for g in ed["testGroups"]:
    if g["parameterSet"] != ps: continue
    for t in g["tests"]:
        if g["function"] == "decapsulationKeyCheck":
            vs.append({"name": f"tc{t['tcId']}-checkDK-{t['reason'].replace(' ', '_')}", "mode": "checkDK",
                       "dk_hex": t["dk"], "want_pass": t["testPassed"], "reason": t["reason"]})
        elif g["function"] == "encapsulationKeyCheck":
            vs.append({"name": f"tc{t['tcId']}-checkEK-{t['reason'].replace(' ', '_')}", "mode": "checkEK",
                       "ek_hex": t["ek"], "want_pass": t["testPassed"], "reason": t["reason"]})
write("keycheck", src + f"ML-KEM-encapDecap-FIPS203/internalProjection.json, {ps} decapsulationKeyCheck + encapsulationKeyCheck test groups",
      f"Official NIST ACVP known-answer vectors for FIPS 203's {ps} input-validation checks: the decapsulation-key hash check (Section 7.3, dk.ekHash vs a fresh H(ekPKE) recomputation -- 'modified H' cases must fail) and the encapsulation-key modulus check (Section 7.2, decode-then-re-encode ek.tHatEncoded must reproduce the same bytes -- 'noisy linear system values too large' cases have an out-of-range coefficient and must fail).",
      vs)
