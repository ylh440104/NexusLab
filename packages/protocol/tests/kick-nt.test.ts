// StatusService.KickNT (forced-offline push) → bot_offline event.
// Command + field layout RE-confirmed against wrapper.linux.node + Lagrange's
// KickNTService/ServiceKickNTResponse (f4 = tips_title, f3 = tips_content).

import { describe, expect, it } from 'vitest';
import { protobuf_encode } from '@nexuslab/proton';
import { parseKickNT, KICK_NT_CMD } from '@nexuslab/protocol/kick-nt';
import { IdentityService } from '@nexuslab/protocol/identity-service';
import type { KickNTResponse } from '@nexuslab/proto-defs/notify';
import type { PacketInfo } from '@nexuslab/common/protocol-types';
import type { QQEventVariant } from '@nexuslab/protocol/events';

type BotOfflineEvent = Extract<QQEventVariant, { kind: 'bot_offline' }>;

describe('parseKickNT (StatusService.KickNT → bot_offline)', () => {
    const identity = IdentityService.memory('3433035623');

    function pkt(resp: KickNTResponse, uin = '3433035623'): PacketInfo {
        return {
            pid: 1,
            uin,
            serviceCmd: KICK_NT_CMD,
            seqId: 1,
            retCode: 0,
            fromClient: false,
            body: protobuf_encode<KickNTResponse>(resp),
        };
    }

    it('emits bot_offline with tag=title (f4) and message=tips (f3)', () => {
        const [ev] = parseKickNT(
            pkt({ uin: 3433035623, title: '你已离线', tips: '你的账号在其他设备登录' }),
            identity,
        ) as BotOfflineEvent[];

        expect(ev.kind).toBe('bot_offline');
        expect(ev.selfUin).toBe(3433035623);
        expect(ev.tag).toBe('你已离线');
        expect(ev.message).toBe('你的账号在其他设备登录');
    });

    it('falls back to the identity uin when the packet uin is missing', () => {
        const [ev] = parseKickNT(pkt({ title: 't', tips: 'm' }, ''), identity) as BotOfflineEvent[];
        expect(ev.selfUin).toBe(3433035623);
    });
});
