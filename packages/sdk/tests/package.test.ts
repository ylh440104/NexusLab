import { spawnSync } from 'node:child_process';
import {
    copyFileSync,
    cpSync,
    mkdirSync,
    mkdtempSync,
    readFileSync,
    rmSync,
    symlinkSync,
    writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, it } from 'vitest';

const sdkRoot = fileURLToPath(new URL('..', import.meta.url));
const compiler = createRequire(import.meta.url).resolve('typescript/bin/tsc');
const manifest = JSON.parse(readFileSync(path.join(sdkRoot, 'package.json'), 'utf8')) as {
    name: string;
    exports: Record<string, string | { import: string; types: string }>;
};
const entrypoints = Object.entries(manifest.exports)
    .filter(([, target]) => typeof target !== 'string')
    .map(([entry]) => `${manifest.name}${entry === '.' ? '' : entry.slice(1)}`);
let consumerRoot: string;

function node(args: string[]): void {
    const result = spawnSync(process.execPath, args, {
        cwd: consumerRoot,
        encoding: 'utf8',
        stdio: 'pipe',
        timeout: 30_000,
    });

    if (result.error) {
        throw result.error;
    }

    if (result.status !== 0) {
        throw new Error(
            `Node exited with status ${result.status} (signal ${result.signal}):\n${result.stdout}\n${result.stderr}`,
        );
    }
}

beforeAll(() => {
    consumerRoot = mkdtempSync(path.join(tmpdir(), 'nexuslab-sdk-package-'));
    const installed = path.join(consumerRoot, 'node_modules', '@nexuslab', 'sdk');
    mkdirSync(installed, { recursive: true });
    copyFileSync(path.join(sdkRoot, 'package.json'), path.join(installed, 'package.json'));
    // Install the declared runtime dependency into this isolated consumer. Node
    // type declarations belong to the consuming Node project's dev environment.
    const require = createRequire(import.meta.url);
    cpSync(
        path.dirname(require.resolve('ws/package.json')),
        path.join(consumerRoot, 'node_modules', 'ws'),
        { recursive: true },
    );
    mkdirSync(path.join(consumerRoot, 'node_modules', '@types'), { recursive: true });
    symlinkSync(
        path.dirname(require.resolve('@types/node/package.json')),
        path.join(consumerRoot, 'node_modules', '@types', 'node'),
        'dir',
    );

    copyFileSync(
        path.join(sdkRoot, 'tests', 'fixtures', 'action-types.mts'),
        path.join(consumerRoot, 'action-types.mts'),
    );
    copyFileSync(
        path.join(sdkRoot, 'tests', 'fixtures', 'action-contracts.ts'),
        path.join(consumerRoot, 'action-contracts.ts'),
    );
    copyFileSync(
        path.join(sdkRoot, 'tests', 'fixtures', 'messaging-types.mts'),
        path.join(consumerRoot, 'messaging-types.mts'),
    );

    writeFileSync(
        path.join(consumerRoot, 'reverse-types.mts'),
        `import { text } from '@nexuslab/sdk';
import { createReverseWebSocketServer, type NexusLabReverseWebSocketSession } from '@nexuslab/sdk/node';
const reverse = createReverseWebSocketServer({ port: 0, selfIds: ['10001'] });
reverse.on('connection', (bot: NexusLabReverseWebSocketSession) => {
    const id: string = bot.selfId;
    const ready: boolean = bot.canCallActions;
    void bot.getStatus();
    bot.onMessage(async (_event, context) => { await context.reply(text(id)); });
    void ready;
});
`,
    );

    writeFileSync(
        path.join(consumerRoot, 'browser-types.mts'),
        `
import { NexusLabWebSocketClient, text } from '@nexuslab/sdk';
new NexusLabWebSocketClient().onMessage(async (_event, context) => { await context.reply(text('hello')); });
// @ts-expect-error Node globals must not leak through the browser entry.
process.cwd();
`,
    );
    writeFileSync(
        path.join(consumerRoot, 'tsconfig.browser.json'),
        JSON.stringify({
            compilerOptions: {
                strict: true,
                noEmit: true,
                target: 'ES2022',
                lib: ['ES2022', 'DOM'],
                module: 'ESNext',
                moduleResolution: 'Bundler',
                types: [],
            },
            files: ['browser-types.mts'],
        }),
    );

    // Compile fresh output outside the workspace so neither stale dist files nor
    // Vitest's source resolver can hide a broken published entry point.
    node([
        compiler,
        '--project',
        path.join(sdkRoot, 'tsconfig.json'),
        '--outDir',
        path.join(installed, 'dist'),
    ]);
    writeFileSync(
        path.join(consumerRoot, 'consumer.mts'),
        `import { NexusLabHttpClient, text, type NexusLabKnownAction as RootKnownAction } from '@nexuslab/sdk';
import { NexusLabWebSocketClient, type NexusLabHttpClientOptions } from '@nexuslab/sdk/client';
import { MessageChain } from '@nexuslab/sdk/messages';
import { isMessageEvent, type EventMiddleware } from '@nexuslab/sdk/events';
import { NexusLabApiError } from '@nexuslab/sdk/errors';
import { NEXUSLAB_ACTIONS, isNexusLabAction, type NexusLabKnownAction } from '@nexuslab/sdk/actions';
import type { ActionParams, StatusInfo } from '@nexuslab/sdk/types';

const options: NexusLabHttpClientOptions = { baseUrl: 'http://127.0.0.1:3000/' };
const client = new NexusLabHttpClient(options);
const status: Promise<StatusInfo> = client.getStatus();
const message: MessageChain = text('hello').reply(-42);
const params: ActionParams<'send_group_msg'> = { group_id: 123, message: [] };
client.raw('send_group_msg', params);
client.raw('consumer_extension', { custom: true });
client.sendGroupMessage(123, message);
const middleware: EventMiddleware = async (event, context, next) => {
    if (isMessageEvent(event)) await context.reply(text('received'));
    await next();
};
new NexusLabWebSocketClient().use(middleware);
const action: RootKnownAction = NEXUSLAB_ACTIONS[0];
function known(value: string): NexusLabKnownAction | null {
    return isNexusLabAction(value) ? value : null;
}
const error = new NexusLabApiError({ status: 'failed', retcode: 1, data: null });
export { status, action, known, error };
`,
    );
}, 30_000);

afterAll(() => {
    if (consumerRoot) {
        rmSync(consumerRoot, { recursive: true, force: true });
    }
});

describe('SDK package entry points', () => {
    it('keeps browser consumers independent of Node server declarations', () => {
        node([compiler, '-p', path.join(consumerRoot, 'tsconfig.browser.json')]);
    }, 30_000);

    it('starts the published Node reverse server without workspace resolution', () => {
        node([
            '--input-type=module',
            '--eval',
            `
import assert from 'node:assert/strict';
import { createReverseWebSocketServer } from '@nexuslab/sdk/node';
const server = createReverseWebSocketServer({ port: 0 });
await server.listen();
assert.ok(server.address.port > 0);
await server.close();
`,
        ]);
    });

    it.each(entrypoints)('loads %s in native Node without a bundler', (entrypoint) => {
        node(['--input-type=module', '--eval', `await import(${JSON.stringify(entrypoint)});`]);
    });

    it('preserves runtime identities across the root and subpath exports', () => {
        node([
            '--input-type=module',
            '--eval',
            `import assert from 'node:assert/strict';
import * as sdk from '@nexuslab/sdk';
import * as client from '@nexuslab/sdk/client';
import * as messages from '@nexuslab/sdk/messages';
import * as events from '@nexuslab/sdk/events';
import * as errors from '@nexuslab/sdk/errors';
import * as actions from '@nexuslab/sdk/actions';
assert.equal(sdk.NexusLabHttpClient, client.NexusLabHttpClient);
assert.equal(sdk.NexusLabWebSocketClient, client.NexusLabWebSocketClient);
assert.equal(sdk.MessageChain, messages.MessageChain);
assert.equal(sdk.quoteMessage, messages.quoteMessage);
assert.equal(sdk.isMessageEvent, events.isMessageEvent);
assert.equal(sdk.NexusLabApiError, errors.NexusLabApiError);
assert.equal(sdk.NexusLabMediaSendError, errors.NexusLabMediaSendError);
assert.equal(sdk.NEXUSLAB_ACTIONS, actions.NEXUSLAB_ACTIONS);
assert.equal(sdk.isNexusLabAction, actions.isNexusLabAction);
assert.ok(sdk.text('hello') instanceof messages.MessageChain);
assert.equal(actions.isNexusLabAction('send_group_msg'), true);
assert.equal(actions.isNexusLabAction('consumer_extension'), false);
`,
        ]);
    });

    it.each([
        ['NodeNext', 'NodeNext'],
        ['ESNext', 'Bundler'],
    ])(
        'typechecks a consumer using %s / %s',
        (module, resolution) => {
            node([
                compiler,
                '--noEmit',
                '--strict',
                '--target',
                'ES2022',
                '--lib',
                'ES2022,DOM',
                '--module',
                module,
                '--moduleResolution',
                resolution,
                path.join(consumerRoot, 'consumer.mts'),
                path.join(consumerRoot, 'action-types.mts'),
                path.join(consumerRoot, 'messaging-types.mts'),
            ]);
            node([
                compiler,
                '--noEmit',
                '--strict',
                '--target',
                'ES2022',
                '--lib',
                'ES2022,DOM',
                '--types',
                'node',
                '--module',
                module,
                '--moduleResolution',
                resolution,
                path.join(consumerRoot, 'reverse-types.mts'),
            ]);
        },
        30_000,
    );
});
