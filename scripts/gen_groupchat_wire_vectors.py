"""Group chat wire vectors from katzenqt's Python (``katzenqt/models.py``,
``katzenqt/acks.py``): messages as CBOR and what a member reads of them,
membership hashes, and the reply to a new member.

    KATZENQT_DIR/.venv/bin/python scripts/gen_groupchat_wire_vectors.py KATZENQT_DIR \
        > testdata/groupchat_wire_vectors.json

Needs katzenqt's dependencies (pydantic, cbor2), so run it with katzenqt's
Python. Seeded, so the output depends only on katzenqt.
"""

import json
import random
import sys
from pathlib import Path

import cbor2

sys.path.insert(0, str(Path(sys.argv[1]) / "src"))
from katzenqt import ack_codec, acks, models  # noqa: E402
from katzenqt.groupchat import wire  # noqa: E402

rng = random.Random(166)


def rb(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


def message_json(m: "wire.Message | None") -> "dict | None":
    if m is None:
        return None
    return {
        "content": m.content.hex() if m.content is not None else None,
        "introduction": (
            {"name": m.introduction.name, "read_cap": m.introduction.read_cap.hex()}
            if m.introduction is not None else None
        ),
        "numbers": [[k, p.hex() if p is not None else None] for k, p in m.numbers],
        "introduced_at": (
            {"introducer": m.introduced_at.introducer, "index": m.introduced_at.index.hex()}
            if m.introduced_at is not None else None
        ),
        "acks": [[i, v] for i, v in sorted(m.acks.items())],
    }


caps = [rb(136) for _ in range(4)]
hash_ = models.canonical_membership_hash(caps[:3])

messages = []


def read_case(name: str, cbor: bytes) -> None:
    """What a member reads of ``cbor``, and the CBOR it is written back as."""
    m = acks.CODEC.decode(cbor)
    case = {"name": name, "cbor": cbor.hex(), "message": message_json(m)}
    if m is not None:
        case["rewritten"] = acks.CODEC.encode(m).hex()
    messages.append(case)


def gcm(**fields) -> bytes:
    return models.GroupChatMessage(**fields).to_cbor()


read_case("text", gcm(version=3, membership_hash=hash_, text="hello"))
read_case("text-unicode", gcm(version=3, membership_hash=hash_, text="grüße, 世界 🙂"))
read_case("text-long", gcm(version=3, membership_hash=hash_, text="x" * 1000))
read_case("text-with-acks", gcm(
    version=3, membership_hash=hash_, text="seen",
    acks=ack_codec.encode({0: 7, 2: 2**64 - 1}),
))
read_case("control", gcm(
    version=3, membership_hash=bytes(32), msg_type=models.GroupChatTypeEnum.CONTROL,
    numbers=wire.encode_numbers(((3, caps[0][:8]), (4, caps[1][:8]))),
    introduced_at=wire.encode_introduced_at(wire.IntroRef(1, rb(104))),
    acks=ack_codec.encode({i: rng.getrandbits(64) for i in range(12)}),
))
read_case("introduction", gcm(
    version=3, membership_hash=bytes(32), msg_type=models.GroupChatTypeEnum.INTRODUCTION,
    introduction=models.GroupChatPleaseAdd(display_name="carol", read_cap=caps[3]),
    numbers=wire.encode_numbers(((5, None),)),
))
read_case("file-upload", gcm(
    version=3, membership_hash=hash_,
    file_upload=models.GroupChatFileUpload(payload=rb(40), filetype="arbitrary",
                                           basename="notes.txt"),
))
read_case("legacy-who", cbor2.dumps({"version": 0, "membership_hash": bytes(32), "who": "alice"}))
read_case("legacy-text", cbor2.dumps({"version": 1, "membership_hash": bytes(32), "text": "hi"}))
read_case("unknown-key", cbor2.dumps(
    {"version": 3, "membership_hash": hash_, "msg_type": 0, "text": "hi", "zzz": [1, {"a": b"b"}]}))
read_case("null-fields", cbor2.dumps(
    {"version": 3, "membership_hash": hash_, "msg_type": 0, "text": "hi", "acks": None,
     "numbers": None}))
read_case("newer-version", cbor2.dumps({"version": 4, "membership_hash": hash_, "text": "hi"}))
read_case("short-hash", cbor2.dumps({"version": 3, "membership_hash": bytes(31), "text": "hi"}))
read_case("not-a-map", cbor2.dumps([1, 2, 3]))
read_case("garbage", b"\xff\x00")
read_case("bad-acks", gcm(version=3, membership_hash=hash_, text="x", acks=b"\x05\x01"))

written = []
for name, m in (
    ("control-numbers", wire.Message(numbers=((0, caps[0][:8]), (1, caps[1][:8])))),
    ("introduction", wire.Message(
        introduction=wire.Introduction("dave", caps[2]), numbers=((2, None),))),
    ("control-introduced-at", wire.Message(
        introduced_at=wire.IntroRef(0, rb(104)), acks={1: 9, 3: 2**40})),
    ("content-acks", wire.Message(
        content=gcm(version=3, membership_hash=hash_, text="again"), acks={0: 1})),
):
    written.append({"name": name, "message": message_json(m),
                    "box": (b"F" + acks.CODEC.encode(m)).hex()})

membership = []
for n in (0, 1, 2, 3, 4):
    chosen = caps[:n]
    membership.append({"read_caps": [c.hex() for c in chosen],
                       "hash": models.canonical_membership_hash(chosen).hex()})
# The same member by another read cap counts once.
membership.append({"read_caps": [caps[0].hex(), (caps[0][:32] + rb(104)).hex(), caps[1].hex()],
                   "hash": models.canonical_membership_hash(
                       [caps[0], caps[0][:32] + rb(104), caps[1]]).hex()})


def join_json(j: "acks.JoinReply | None") -> "dict | None":
    if j is None:
        return None
    return {
        "members": [[c.hex(), s.hex()] if m is not None else None
                    for m in j.members for c, s in [m or (b"", b"")]],
        "rosters": [[[i, s] for i, s in r] if r is not None else None for r in j.rosters],
        "introductions": [[b, i.hex(), m] for b, i, m in j.introductions],
        "introducer": j.introducer,
        "newcomer": j.newcomer,
    }


def add(name: str, cap: bytes) -> models.GroupChatPleaseAdd:
    return models.GroupChatPleaseAdd(display_name=name, read_cap=cap)


replies = []
for name, who in (
    ("plain", models.GroupChatReplyWho(please_adds=[add("alice", caps[0])])),
    ("rosters", models.GroupChatReplyWho(
        please_adds=[add("alice", caps[0]), None, add("bob", caps[1])],
        rosters=[[(0, 0), (1, None), (2, 2)], None, [(0, 0), (1, 2)]],
        introductions=[(0, rb(104), 2)], introducer=0, newcomer=3)),
    ("two", models.GroupChatReplyWho(
        please_adds=[add("alice", caps[0]), add("bob", caps[1])],
        rosters=[[(0, 0), (1, 1)], [(0, 1), (1, 0)]],
        introductions=[], introducer=1, newcomer=2)),
    ("wrong-newcomer", models.GroupChatReplyWho(
        please_adds=[add("alice", caps[0])], rosters=[[(0, 0)]],
        introductions=[], introducer=0, newcomer=5)),
    ("duplicate-key", models.GroupChatReplyWho(
        please_adds=[add("alice", caps[0]), add("alias", caps[0][:32] + rb(104))],
        rosters=[None, None], introductions=[], introducer=0, newcomer=2)),
):
    replies.append({"name": name, "cbor": who.to_cbor().hex(),
                    "join_reply": join_json(acks._join_reply(who))})

json.dump({
    "about": "Group chat wire vectors from katzenqt (models.py, acks.py), generated by "
             "scripts/gen_groupchat_wire_vectors.py. messages: a message's CBOR, what a member "
             "reads of it (null when katzenqt refuses it) and the CBOR katzenqt writes it back as. "
             "written: what a member's message is written as, a whole box. membership: "
             "canonical_membership_hash of read caps. replies: GroupChatReplyWho CBOR and the "
             "JoinReply it carries (null when it carries none).",
    "messages": messages,
    "written": written,
    "membership": membership,
    "replies": replies,
}, sys.stdout, indent=1)
print()
