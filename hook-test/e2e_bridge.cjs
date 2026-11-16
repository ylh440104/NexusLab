const net = require('net');
const path = require('path');

const RUNTIME_DIR = process.env.NEXUSLAB_RUNTIME_DIR;
const PID = process.pid;
const CONTROL = path.join(RUNTIME_DIR, 'mojo.' + PID + '.control.sock');
const VARIANT = parseInt(process.env.MOCK_VARIANT || '0', 10);

const EXPECT = {
    0: { body: 'ack:trpc.Roundtrip.Test:10', payload: 'PAYLOAD123', label: 'two-arg' },
    1: { body: 'one:trpc.Roundtrip.Test', payload: '', label: 'one-arg' },
    2: { body: 'resolved-value', payload: 'PAYLOAD123', label: 'promise' },
};
const expect = EXPECT[VARIANT];

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

async function pump(ms) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
        await new Promise(r => setTimeout(r, 25));
    }
}

async function main() {
    const addon = require('./mock_addon.node');
    check('addon loaded', typeof addon === 'object');
    console.log('variant: ' + expect.label);

    const frames = [];
    let pending = Buffer.alloc(0);
    const sock = net.createConnection(CONTROL);
    sock.on('data', (chunk) => {
        pending = Buffer.concat([pending, chunk]);
        while (pending.length >= 40) {
            if (pending.slice(0, 4).toString('ascii') !== 'QHP1') { pending = Buffer.alloc(0); break; }
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
                        ' status=' + status + ' body=' + JSON.stringify(body.toString('utf8').slice(0, 50)));
        }
    });

    await pump(700);
    check('hello received', frames.some(f => f.op === 1));

    const before = frames.length;
    const reqId = 200 + VARIANT;
    sock.write(buildFrame(2, reqId, 1, 'trpc.Roundtrip.Test', Buffer.from('PAYLOAD123')));
    await pump(900);

    const ack = frames.slice(before).find(f => f.op === 3 && f.reqId === reqId);
    check('send ack', !!ack);

    const reply = frames.slice(before).find(f => f.op === 4 && f.reqId === reqId);
    check('reply received', !!reply);
    if (reply) {
        check('reply body', reply.body.toString('utf8') === expect.body,
              JSON.stringify(reply.body.toString('utf8')));
    }

    const stats = addon.getStats();
    check('target executed', stats.targetCalls >= 1, 'calls=' + stats.targetCalls);
    if (expect.payload) {
        check('payload delivered', stats.lastPayload === expect.payload,
              JSON.stringify(stats.lastPayload));
    }

    await pump(120);
    sock.destroy();
    console.log(failures === 0 ? 'E2E_ALL_PASS' : 'E2E_FAILURES=' + failures);
    setTimeout(() => process.exit(failures === 0 ? 0 : 1), 100);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
