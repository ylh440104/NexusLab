// Vitest config — runs the OneBot tests against the workspace TS
// source directly (no build step). The 20 tests here were previously
// inside `packages/core/tests/` and ran via `@nexuslab/core`'s vitest
// invocation; they moved over wholesale in the Phase 3 split.
import protobufVitePlugin from '@nexuslab/proton/vite';
import { defineConfig } from 'vitest/config';

export default defineConfig({
    // `@nexuslab/proton` provides the bare-specifier resolver that turns
    // `import type { OidbBase } from '@nexuslab/proto-defs/oidb'` into
    // a zero-runtime encoder/decoder at the call site. The same plugin
    // is loaded by `@nexuslab/core`'s vite config — keep it here so the
    // OneBot tests resolve identically.
    plugins: [protobufVitePlugin()],
    test: {
        include: ['tests/**/*.test.ts'],
        setupFiles: ['./tests/setup.ts'],
        // Per-RoadMap-#5 bench files live in `bench/*.bench.ts`. Use the
        // vitest `--mode bench` (via `pnpm bench`) to pick them up; default
        // `test` runs leave them inert.
        benchmark: {
            include: ['bench/**/*.bench.ts'],
        },
        environment: 'node',
        // Suppress the logger's file transport during tests so the suite
        // doesn't litter cwd with logs/nexuslab-*.log files. Tests that
        // explicitly cover file output set their own NEXUSLAB_LOG_FILE='1'
        // + NEXUSLAB_LOG_DIR=<tmp>.
        //
        // Run at debug level so tests asserting on debug-level log entries
        // (e.g. action dispatch entry lines) actually see them via the
        // ring buffer / subscribers, which sit behind the console-level
        // gate. Mirrors the equivalent env setup in @nexuslab/core's
        // vitest.config.ts.
        env: {
            NEXUSLAB_LOG_FILE: '0',
            NEXUSLAB_LOG_LEVEL: 'debug',
        },
    },
});
