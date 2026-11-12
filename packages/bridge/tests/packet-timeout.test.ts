import { afterEach, describe, expect, it } from 'vitest';
import { QqHookClient } from '../src/qq-hook-client';
import { packetTimeoutMs } from '../src/packet-timeout';

const PACKET = 'NEXUSLAB_PACKET_TIMEOUT_MS';
const ACK = 'NEXUSLAB_HOOK_ACK_TIMEOUT_MS';

afterEach(() => {
    delete process.env[PACKET];
    delete process.env[ACK];
});

describe('packet and hook ack timeouts', () => {
    it('keeps the 15 second packet default', () => {
        expect(packetTimeoutMs({})).toBe(15_000);
    });

    it('reads NEXUSLAB_PACKET_TIMEOUT_MS', () => {
        expect(packetTimeoutMs({ [PACKET]: '8000' })).toBe(8000);
        expect(packetTimeoutMs({ [PACKET]: '0' })).toBe(15_000);
    });

    it('uses NEXUSLAB_HOOK_ACK_TIMEOUT_MS when the client is not given one', () => {
        process.env[ACK] = '1200';
        const client = new QqHookClient(1, { runtimeDir: '/tmp' });
        expect(client.defaultAckTimeoutMs).toBe(1200);
        const explicit = new QqHookClient(1, { runtimeDir: '/tmp', ackTimeoutMs: 50 });
        expect(explicit.defaultAckTimeoutMs).toBe(50);
    });
});
