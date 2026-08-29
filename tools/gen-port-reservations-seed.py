#!/usr/bin/env python3
"""Regenerate regim/port-reservations.reg — the shipped port reservation seed.

The descriptors are hand-assembled self-relative SDs (owner/group SYSTEM, one
ACCESS_ALLOWED ACE per grantee carrying PORT_BIND | READ_CONTROL). The
bindLowPorts capability SID follows PCDS's derived-capability rule: eight
little-endian u32 sub-authorities from SHA-256 of the UTF-8 capability name.
"""
import hashlib, json, os, struct, sys

def sid(auth, subs):
    return bytes([1, len(subs)]) + auth.to_bytes(6, 'big') + b''.join(struct.pack('<I', s) for s in subs)

SYSTEM, EVERYONE = sid(5, [18]), sid(1, [0])
PORT_BIND, READ_CONTROL = 0x1, 0x20000

def capability(name):
    h = hashlib.sha256(name.encode('utf-8')).digest()
    subs = [struct.unpack('<I', h[i:i + 4])[0] for i in range(0, 32, 4)]
    return sid(15, [3] + subs), 'S-1-15-3-' + '-'.join(map(str, subs))

def ace(s, mask):
    return bytes([0, 0]) + struct.pack('<H', 8 + len(s)) + struct.pack('<I', mask) + s

def sd(aces):
    body = b''.join(aces)
    acl = bytes([2, 0]) + struct.pack('<HHH', 8 + len(body), len(aces), 0) + body
    owner, group = 20, 20 + len(SYSTEM)
    hdr = bytes([1, 0]) + struct.pack('<H', 0x8004) + struct.pack('<IIII', owner, group, 0, group + len(SYSTEM))
    return hdr + SYSTEM + SYSTEM + acl

def main():
    cap, capstr = capability('bindLowPorts')
    out = os.path.join(os.path.dirname(__file__), '..', 'regim', 'port-reservations.reg')
    doc = json.load(open(out))
    values = doc['keys'][-1]['values']
    values[0]['data'] = sd([ace(EVERYONE, PORT_BIND | READ_CONTROL)]).hex()
    values[1]['data'] = sd([ace(SYSTEM, PORT_BIND | READ_CONTROL), ace(cap, PORT_BIND | READ_CONTROL)]).hex()
    doc['_comment'] = [l if 'S-1-15-3-' not in l else '                   ' + capstr + ' is the derived capability SID for the name' for l in doc['_comment']]
    json.dump(doc, open(out, 'w'), indent=2); open(out, 'a').write('\n')
    print(capstr)

if __name__ == '__main__':
    sys.exit(main())
