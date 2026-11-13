import type { OneBotConfig } from '@/types';

export interface SplitDefaultTokenReport {
    httpNames: string[];
    wsNames: string[];
    sharedToken: string;
}

const HTTP_DEFAULT_SERVER = 'http-default';
const WS_DEFAULT_SERVER = 'ws-default';

export function detectSplitDefaultAccessToken(
    config: OneBotConfig,
): SplitDefaultTokenReport | null {
    const http = config.networks.httpServers.find((a) => a.name === HTTP_DEFAULT_SERVER);
    const ws = config.networks.wsServers.find((a) => a.name === WS_DEFAULT_SERVER);
    if (!http || !ws) {
        return null;
    }
    const httpToken = http.accessToken ?? '';
    const wsToken = ws.accessToken ?? '';
    if (!httpToken || !wsToken || httpToken === wsToken) {
        return null;
    }
    return {
        httpNames: [HTTP_DEFAULT_SERVER],
        wsNames: [WS_DEFAULT_SERVER],
        sharedToken: httpToken,
    };
}

export function applySharedDefaultAccessToken(
    config: OneBotConfig,
    report: SplitDefaultTokenReport,
): OneBotConfig {
    const next = structuredClone(config);
    for (const adapter of next.networks.httpServers) {
        if (report.httpNames.includes(adapter.name)) {
            adapter.accessToken = report.sharedToken;
        }
    }
    for (const adapter of next.networks.wsServers) {
        if (report.wsNames.includes(adapter.name)) {
            adapter.accessToken = report.sharedToken;
        }
    }
    return next;
}
