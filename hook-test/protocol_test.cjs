const net = require('net');
const path = require('path');
const fs = require('fs');

const RUNTIME_DIR = process.env.NEXUSLAB_RUNTIME_DIR;
const PID = process.pid;
const CONTROL = path.join(RUNTIME_DIR, 'mojo.' + PID + '.control.sock');

let failures = 0;
function check(name, ok, detail) {
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  [' + detail + ']' : ''));
    if (!ok) failures++;
}

function parseHeader(buf) {
    if (buf.length < 40) return null;
    return {
        magic: buf.slice(0, 4).toString('ascii'),
        version: buf.readUInt16LE(4),
        op: buf.readUInt16LE(6),
        requestId: buf.readUInt32LE(8),
        status: buf.readInt32LE(12),
        flags: buf.readUInt32LE(16),
        cmdLen: buf.readUInt32LE(20),
        msgLen: buf.readUInt32LE(24),
        bodyLen: buf.readUInt32LE(28),
        value0: buf.readBigUInt64LE(32)
    };
}

async function main() {
    check('runtime dir exists', fs.existsSync(RUNTIME_DIR), RUNTIME_DIR);

    let connected = false;
    let helloFrame = null;

    const sock = net.createConnection(CONTROL);
    sock.on('connect', () => { connected = true; });

    let pending = Buffer.alloc(0);
    sock.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 40) {
            const h = parseHeader(pending);
            if (!h) break;
            const total = 40 + h.bodyLen;
            if (pending.length < total) break;
            const body = pending.slice(40, total).toString('utf8');
            pending = pending.slice(total);
            console.log('  frame: op=' + h.op + ' magic=' + h.magic +
                        ' ver=' + h.version + ' reqId=' + h.requestId +
                        ' status=' + h.status + ' body=' + JSON.stringify(body.slice(0, 60)));
            if (h.op === 1 && helloFrame === null) helloFrame = h;
        }
    });

    await new Promise(r => setTimeout(r, 800));
    check('control socket connectable', connected, CONTROL);
    check('received HELLO frame', helloFrame !== null);
    if (helloFrame) {
        check('HELLO magic is QHP1', helloFrame.magic === 'QHP1', helloFrame.magic);
        check('HELLO version is 1', helloFrame.version === 1, String(helloFrame.version));
    }

    sock.destroy();
    console.log(failures === 0 ? 'PROTOCOL_ALL_PASS' : 'PROTOCOL_FAILURES=' + failures);
    process.exit(failures === 0 ? 0 : 1);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
