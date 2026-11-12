import sys

SOURCE = sys.argv[1]
TARGET = sys.argv[2]

data = open(SOURCE, 'rb').read()

lines = []
lines.append('#include "resident_blob.h"')
lines.append('')
lines.append('extern "C" {')
lines.append('')
lines.append('const unsigned char kNexuslabResidentImage[] = {')

for offset in range(0, len(data), 16):
    chunk = data[offset:offset + 16]
    rendered = ', '.join('0x%02X' % byte for byte in chunk)
    lines.append('    ' + rendered + ',')

lines.append('};')
lines.append('')
lines.append('const unsigned long kNexuslabResidentImageSize = %dUL;' % len(data))
lines.append('')
lines.append('}')

open(TARGET, 'w', encoding='utf-8').write('\n'.join(lines) + '\n')
print('BLOB_OK %s bytes -> %s' % (len(data), TARGET))
