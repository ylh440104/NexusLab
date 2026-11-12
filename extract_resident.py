import struct
import sys

SRC = sys.argv[1] if len(sys.argv) > 1 else "packages/runtime/native/nexuslab-win32-x64.dll"
DST = sys.argv[2] if len(sys.argv) > 2 else "out/resident.dll"
DATA_RVA = 0x44340
DATA_SIZE = 0x1dc00

data = open(SRC, 'rb').read()

pe_off = struct.unpack_from('<I', data, 0x3C)[0]
coff = pe_off + 4
nsec = struct.unpack_from('<H', data, coff + 2)[0]
optsz = struct.unpack_from('<H', data, coff + 16)[0]
opt = coff + 20
sec_off = opt + optsz

sections = []
for i in range(nsec):
    b = sec_off + i * 40
    name = data[b:b + 8].rstrip(b'\0').decode('latin1')
    vs, va, rs, rp = struct.unpack_from('<IIII', data, b + 8)
    sections.append((name, va, vs, rp, rs))


def rva_to_off(rva):
    for name, va, vs, rp, rs in sections:
        if va <= rva < va + max(vs, rs):
            delta = rva - va
            if delta >= rs:
                return None
            return rp + delta
    return None


off = rva_to_off(DATA_RVA)
if off is None:
    print("EMBED_NOT_FOUND")
    sys.exit(1)

blob = data[off:off + DATA_SIZE]
if len(blob) != DATA_SIZE:
    print("EMBED_TRUNCATED", len(blob))
    sys.exit(1)

if blob[:2] != b'MZ':
    print("EMBED_NOT_PE")
    sys.exit(1)

open(DST, 'wb').write(blob)
print("EMBED_OK", DST, len(blob))
