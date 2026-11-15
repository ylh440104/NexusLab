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

const r1 = addon.SendSSORequestInternal('hello-payload');
check('first call returns 1', r1 === 1, 'got ' + r1);

const r2 = addon.SendSSORequestInternal('second-payload');
check('second call returns 2', r2 === 2, 'got ' + r2);

const after = addon.getStats();
check('target actually executed twice', after.targetCalls === 2, 'got ' + after.targetCalls);
check('payload reached original', after.lastPayload === 'second-payload', 'got ' + after.lastPayload);

const rr = addon.RecvPacket();
check('RecvPacket returns 42', rr === 42, 'got ' + rr);

console.log(failures === 0 ? 'ALL_PASS' : 'FAILURES=' + failures);
process.exit(failures === 0 ? 0 : 1);
