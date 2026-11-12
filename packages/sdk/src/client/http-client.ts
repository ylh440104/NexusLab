import {
    NexusLabAbortError,
    NexusLabConnectionError,
    NexusLabParseError,
    NexusLabTimeoutError,
    NexusLabTransportError,
} from '../errors.js';
import { NexusLabApiClient, toJsonObject } from './api-client.js';
import { createRequestAbortState, isAbortError, throwIfAborted } from '../internal/abort.js';
import { assertApiResponse } from '../internal/json.js';
import { isStreamTerminal, readHttpFrames, streamLimits } from '../internal/streaming.js';
import type {
    ActionParams,
    ActionResult,
    ApiResponse,
    JsonObject,
    RequestOptions,
    NexusLabAction,
    NexusLabClientOptions,
    NexusLabStreamAction,
    StreamApiResponse,
    StreamRequestOptions,
} from '../types/index.js';

/** Options for the HTTP transport client. */
export interface NexusLabHttpClientOptions extends NexusLabClientOptions {
    /** OneBot HTTP endpoint. Defaults to http://127.0.0.1:3000/. */
    baseUrl?: string;
    /** Custom fetch implementation for tests or non-standard runtimes. */
    fetch?: typeof fetch;
    /** Extra headers sent with every request. Authorization is managed by accessToken. */
    headers?: Record<string, string>;
}

/** OneBot HTTP client for NexusLab. */
export class NexusLabHttpClient extends NexusLabApiClient {
    readonly baseUrl: string;
    readonly accessToken?: string;
    readonly requestTimeoutMs: number;

    private readonly fetchImpl: typeof fetch;
    private readonly headers: Record<string, string>;

    constructor(options: NexusLabHttpClientOptions = {}) {
        super();
        this.baseUrl = options.baseUrl ?? 'http://127.0.0.1:3000/';
        this.accessToken = options.accessToken;
        this.requestTimeoutMs = options.requestTimeoutMs ?? 30_000;
        this.fetchImpl = options.fetch ?? globalThis.fetch;
        this.headers = options.headers ?? {};

        if (!this.fetchImpl) {
            throw new NexusLabConnectionError('No fetch implementation is available');
        }
    }

    /** Sends one OneBot action over HTTP and returns the raw response envelope. */
    override async request<TAction extends NexusLabAction>(
        action: TAction,
        params?: ActionParams<TAction>,
        options?: RequestOptions,
    ): Promise<ApiResponse<ActionResult<TAction>>> {
        const timeoutMs = options?.timeoutMs ?? this.requestTimeoutMs;
        const abort = createRequestAbortState(timeoutMs, options?.signal);

        try {
            const response = await this.fetchImpl(this.baseUrl, {
                method: 'POST',
                headers: this.createHeaders(),
                body: JSON.stringify({
                    action,
                    params: toJsonObject(params as JsonObject | undefined),
                    echo: options?.echo,
                }),
                signal: abort.signal,
            });

            const text = await response.text();
            let parsed: unknown;

            try {
                parsed = text ? JSON.parse(text) : null;
            } catch (error) {
                throw new NexusLabParseError(`NexusLab returned non-JSON HTTP ${response.status}`, {
                    cause: error,
                });
            }

            const apiResponse = assertApiResponse(parsed) as ApiResponse<ActionResult<TAction>>;
            return apiResponse;
        } catch (error) {
            if (error instanceof NexusLabTransportError) {
                throw error;
            }

            if (isAbortError(error) || abort.signal.aborted) {
                if (abort.isTimedOut()) {
                    throw new NexusLabTimeoutError(
                        `NexusLab request timed out after ${timeoutMs}ms`,
                        timeoutMs,
                        { cause: error },
                    );
                }

                if (abort.isExternallyAborted()) {
                    throw new NexusLabAbortError('NexusLab request aborted', { cause: error });
                }
            }

            throw new NexusLabConnectionError('NexusLab HTTP request failed', { cause: error });
        } finally {
            abort.cleanup();
        }
    }

    override async *requestStream<TAction extends NexusLabStreamAction>(
        action: TAction,
        params: ActionParams<TAction>,
        options?: StreamRequestOptions,
    ): AsyncGenerator<StreamApiResponse<ActionResult<TAction>>, void, void> {
        const { maxBufferBytes } = streamLimits(options);
        const timeoutMs = options?.timeoutMs ?? this.requestTimeoutMs;
        const abort = createRequestAbortState(timeoutMs, options?.signal);

        try {
            throwIfAborted(abort.signal);
            const response = await this.fetchImpl(this.baseUrl, {
                method: 'POST',
                headers: this.createHeaders(),
                body: JSON.stringify({ action, params, echo: options?.echo }),
                signal: abort.signal,
            });

            if (!response.body) {
                throw new NexusLabParseError('NexusLab HTTP stream has no response body');
            }

            for await (const frame of readHttpFrames(response.body, maxBufferBytes, abort.signal)) {
                throwIfAborted(abort.signal);
                const terminal = isStreamTerminal(action, frame);
                yield frame as StreamApiResponse<ActionResult<TAction>>;

                if (terminal) {
                    return;
                }
            }

            throw new NexusLabParseError('NexusLab HTTP stream ended before its terminal frame');
        } catch (error) {
            if (abort.isTimedOut()) {
                throw new NexusLabTimeoutError(
                    `NexusLab stream timed out after ${timeoutMs}ms`,
                    timeoutMs,
                    { cause: error },
                );
            }

            if (abort.isExternallyAborted()) {
                throw new NexusLabAbortError('NexusLab stream aborted', { cause: error });
            }

            if (error instanceof NexusLabTransportError) {
                throw error;
            }

            throw new NexusLabConnectionError('NexusLab HTTP stream failed', { cause: error });
        } finally {
            abort.cleanup();
        }
    }

    private createHeaders(): Record<string, string> {
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            Accept: 'application/json',
            ...this.headers,
        };

        if (this.accessToken) {
            headers.Authorization = `Bearer ${this.accessToken}`;
        }

        return headers;
    }
}

export function createHttpClient(options?: NexusLabHttpClientOptions): NexusLabHttpClient {
    return new NexusLabHttpClient(options);
}
