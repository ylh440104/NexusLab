const net = require('net');
const path = require('path');
const fs = require('fs');

const RUNTIME_DIR = process.env.NEXUSLAB_RUNTIME_DIR;
const PID = process.pid;
const CONTROL = path.join(RUNTIME_DIR, 'mojo.' + PID + '.control.sock');

const LOGF = '/tmp/proto_trace.log';
function log(msg) {
    try { fs.appendFileSync(LOGF, msg + String.fromCharCode(10)); } catch (e) {}
    console.log(msg);
}

let failures = 0;
function check(name, ok, detail) {
    log((ok ? 'PASS  ' : 'FAIL  ') + name + (detail ? '  [' + detail + ']' : ''));
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
        bodyLen: buf.readUInt32LE(28)
    };
}

function buildFrame(op, requestId, flags, cmd, body) {
    const cmdBuf = Buffer.from(cmd || '', 'utf8');
    const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(body || '');
    const h = Buffer.alloc(40);
    h.write('QHP1', 0, 'ascii');
    h.writeUInt16LE(1, 4);
    h.writeUInt16LE(op, 6);
    h.writeUInt32LE(requestId >>> 0, 8);
    h.writeInt32LE(0, 12);
    h.writeUInt32LE(flags >>> 0, 16);
    h.writeUInt32LE(cmdBuf.length, 20);
    h.writeUInt32LE(0, 24);
    h.writeUInt32LE(bodyBuf.length, 28);
    return Buffer.concat([h, cmdBuf, bodyBuf]);
}

async function main() {
    log('main start');
    check('runtime dir exists', fs.existsSync(RUNTIME_DIR), RUNTIME_DIR);

    log('connecting ' + CONTROL);
    const sock = net.createConnection(CONTROL);
    let connected = false;
    sock.on('connect', () => { connected = true; });

    const frames = [];
    let pending = Buffer.alloc(0);
    sock.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 40) {
            const h = parseHeader(pending);
            const total = 40 + h.bodyLen;
            if (pending.length < total) break;
            const body = pending.slice(40, total);
            pending = pending.slice(total);
            frames.push({ header: h, body });
            console.log('  frame: op=' + h.op + ' magic=' + h.magic +
                        ' reqId=' + h.requestId + ' status=' + h.status +
                        ' bodyLen=' + h.bodyLen);
        }
    });

    for (let i = 0; i < 14; i++) { await new Promise(r => setTimeout(r, 50)); }
    check('control socket connectable', connected, CONTROL);

    const hello = frames.find(f => f.header.op === 1);
    check('received HELLO frame', !!hello);
    if (hello) {
        check('HELLO magic QHP1', hello.header.magic === 'QHP1', hello.header.magic);
        check('HELLO version 1', hello.header.version === 1, String(hello.header.version));
    }

    const login = frames.find(f => f.header.op === 7);
    check('received login-state push (op=7)', !!login);

    console.log('--- sending op=2 send-request ---');
    const before = frames.length;
    const reqId = 777;
    log('writing op=2');
    sock.write(buildFrame(2, reqId, 1, 'trpc.test.Service.Method',
                          Buffer.from([1, 2, 3, 4, 5])));

    for (let i = 0; i < 10; i++) { await new Promise(r => setTimeout(r, 50)); }

    const ack = frames.slice(before).find(f => f.header.op === 3 && f.header.requestId === reqId);
    check('received SEND_ACK (op=3)', !!ack, ack ? 'reqId=' + ack.header.requestId : 'none');
    if (ack) {
        check('ack requestId matches', ack.header.requestId === reqId,
              String(ack.header.requestId));
    }

    const err5 = frames.slice(before).find(f => f.header.op === 5);
    check('no error frame for op=2', !err5);

    await new Promise(r => setTimeout(r, 50));
    sock.destroy();
    console.log(failures === 0 ? 'PROTOCOL_ALL_PASS' : 'PROTOCOL_FAILURES=' + failures);
    setTimeout(() => setTimeout(() => process.exit(failures === 0 ? 0 : 1), 150), 150);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
