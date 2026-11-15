const addon = require('./mock_addon.node');

let failures = 0;
function check(name, ok, detail) {
    console.log((ok ? 'PASS' : 'FAIL') + '  ' + name + (detail ? '  [' + detail + ']' : ''));
    if (!ok) failures++;
}

check('addon loads', typeof addon === 'object');
check('SendSSORequestInternal is function', typeof addon.SendSSORequestInternal === 'function');
check('RecvPacket is function', typeof addon.RecvPacket === 'function');

const before = addon.getStats();
check('initial call count is 0', before.targetCalls === 0, 'got ' + before.targetCalls);

const r1 = addon.SendSSORequestInternal('hello-payload', Buffer.from('abc'));
check('first call returns ack', r1 === 'ack:hello-payload:3', 'got ' + r1);

const r2 = addon.SendSSORequestInternal('second-payload', Buffer.from('de'));
check('second call returns ack', r2 === 'ack:second-payload:2', 'got ' + r2);

const after = addon.getStats();
check('target actually executed twice', after.targetCalls === 2, 'got ' + after.targetCalls);
check('payload reached original', after.lastPayload === 'de', 'got ' + after.lastPayload);

const rr = addon.RecvPacket();
check('RecvPacket returns 42', rr === 42, 'got ' + rr);

const waitMs = parseInt(process.env.HOOK_WAIT_MS || '0', 10);
if (waitMs > 0) {
    console.log('waiting ' + waitMs + 'ms for deferred hook install...');
    const start = Date.now();
    while (Date.now() - start < waitMs) {}
    console.log('calling again after hook install window');
    const r3 = addon.SendSSORequestInternal('after-hook', Buffer.from('xyz'));
    check('post-install ack', r3 === 'ack:after-hook:3', 'got ' + r3);
    const s2 = addon.getStats();
    check('post-install count is 3', s2.targetCalls === 3, 'got ' + s2.targetCalls);
    check('post-install payload', s2.lastPayload === 'xyz', 'got ' + s2.lastPayload);
}

console.log(failures === 0 ? 'ALL_PASS' : 'FAILURES=' + failures);
process.exit(failures === 0 ? 0 : 1);
