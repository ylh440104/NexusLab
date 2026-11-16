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

async function pump(ms) {
    const end = Date.now() + ms;
    while (Date.now() < end) {
        await new Promise(r => setTimeout(r, 25));
    }
}

async function main() {
    const addon = require('./mock_addon.node');
    check('addon loaded', typeof addon === 'object');

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

    console.log('--- A: two-arg target ---');
    addon.setVariant(0);
    await pump(50);
    let before = frames.length;
    sock.write(buildFrame(2, 101, 1, 'trpc.Two.Arg', Buffer.from('PAYLOAD123')));
    await pump(700);
    let reply = frames.slice(before).find(f => f.op === 4 && f.reqId === 101);
    check('A reply received', !!reply);
    if (reply) {
        check('A reply body', reply.body.toString('utf8') === 'ack:trpc.Two.Arg:10',
              JSON.stringify(reply.body.toString('utf8')));
    }
    let stats = addon.getStats();
    check('A target executed', stats.targetCalls >= 1, 'calls=' + stats.targetCalls);
    check('A payload delivered', stats.lastPayload === 'PAYLOAD123', JSON.stringify(stats.lastPayload));

    console.log('--- B: one-arg target (arity adaptation) ---');
    addon.setVariant(1);
    await pump(50);
    before = frames.length;
    sock.write(buildFrame(2, 102, 1, 'trpc.One.Arg', Buffer.from('ignored')));
    await pump(700);
    reply = frames.slice(before).find(f => f.op === 4 && f.reqId === 102);
    check('B reply received', !!reply);
    if (reply) {
        const body = reply.body.toString('utf8');
        check('B uses one-arg function', body === 'one:trpc.One.Arg', JSON.stringify(body));
    }

    console.log('--- C: promise target ---');
    addon.setVariant(2);
    await pump(50);
    before = frames.length;
    sock.write(buildFrame(2, 103, 1, 'trpc.Promise', Buffer.from('abc')));
    await pump(900);
    reply = frames.slice(before).find(f => f.op === 4 && f.reqId === 103);
    check('C reply received (async resolved)', !!reply);
    if (reply) {
        check('C reply body', reply.body.toString('utf8') === 'resolved-value',
              JSON.stringify(reply.body.toString('utf8')));
    }

    await pump(150);
    sock.destroy();
    console.log(failures === 0 ? 'E2E_ALL_PASS' : 'E2E_FAILURES=' + failures);
    setTimeout(() => process.exit(failures === 0 ? 0 : 1), 100);
}

main().catch(e => { console.error('error:', e.message); process.exit(1); });
