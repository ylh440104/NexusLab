import glob
import os
import socket
import struct
import sys

runtime = os.environ.get("XDG_RUNTIME_DIR", "")
roots = []
if runtime:
    roots.append(os.path.join(runtime, "nexuslab"))
roots.append("/tmp/nexuslab")

sockets = []
for root in roots:
    sockets.extend(glob.glob(os.path.join(root, "*.control.sock")))

if not sockets:
    print("RESULT: NO_CONTROL_SOCKET")
    sys.exit(1)

sockets.sort(key=os.path.getmtime)
path = sockets[-1]
print("target socket:", path)

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(10)
try:
    client.connect(path)
except Exception as exc:
    print("RESULT: CONNECT_FAILED", exc)
    sys.exit(1)

buffer = b""
while len(buffer) < 8:
    chunk = client.recv(8 - len(buffer))
    if not chunk:
        break
    buffer += chunk

if len(buffer) < 8:
    print("RESULT: HELLO_TRUNCATED", len(buffer))
    sys.exit(1)

magic = buffer[:4]
opcode = struct.unpack_from("<H", buffer, 6)[0]
peer_pid = struct.unpack_from("<I", buffer, 16)[0] if len(buffer) >= 20 else 0
client.close()

print("magic:", magic)
print("opcode:", opcode)

if magic != b"QHP1":
    print("RESULT: BAD_MAGIC")
    sys.exit(1)
if opcode != 1:
    print("RESULT: UNEXPECTED_OPCODE", opcode)
    sys.exit(1)

print("RESULT: HELLO_OK")
