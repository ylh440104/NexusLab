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
    const addon = require('./mock_addon.node');
    check('addon loaded', typeof addon === 'object');

    const sock = net.createConnection(CONTROL);
    let pending = Buffer.alloc(0);
    const frames = [];
    sock.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 40) {
            const magic = pending.slice(0, 4).toString('ascii');
            if (magic !== 'QHP1') { pending = Buffer.alloc(0); break; }
            const op = pending.readUInt16LE(6);
            const reqId = pending.readUInt32LE(8);
            const status = pending.readInt32LE(12);
            const bodyLen = pending.readUInt32LE(28);
            const total = 40 + bodyLen;
            if (pending.length < total) break;
            const body = pending.slice(40, total);
            pending = pending.slice(total);
            frames.push({ op, reqId, status, body });
            console.log('  frame: op=' + op + ' reqId=' + reqId +
                        ' status=' + status + ' body=' + JSON.stringify(body.toString('utf8').slice(0, 40)));
        }
    });

    await new Promise(r => setTimeout(r, 800));
    check('hello received', frames.some(f => f.op === 1));

    console.log('--- roundtrip: send op=2, expect real function executed ---');
    const before = frames.length;
    const reqId = 9001;
    sock.write(buildFrame(2, reqId, 1, 'trpc.Roundtrip.Test', Buffer.from('PAYLOAD123')));

    for (let i = 0; i < 24; i++) {
        await new Promise(r => setTimeout(r, 50));
    }

    const ack = frames.slice(before).find(f => f.op === 3 && f.reqId === reqId);
    check('send ack (op=3)', !!ack);

    const after = addon.getStats();
    check('target function executed by bridge', after.targetCalls >= 1,
          'calls=' + after.targetCalls);
    check('body payload reached target', after.lastPayload === 'PAYLOAD123',
          JSON.stringify(after.lastPayload));

    await new Promise(r => setTimeout(r, 100));
    sock.destroy();
    console.log(failures === 0 ? 'E2E_ALL_PASS' : 'E2E_FAILURES=' + failures);
    setTimeout(() => setTimeout(() => process.exit(failures === 0 ? 0 : 1), 150), 150);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
