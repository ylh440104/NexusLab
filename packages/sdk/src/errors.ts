import type { ApiResponse, UploadFileStreamComplete } from './types/index.js';

/** Base error for every exception intentionally thrown by the NexusLab SDK. */
export class NexusLabError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabError';
    }
}

/** A one-step media operation failed. The original error is preserved as cause. */
export class NexusLabMediaSendError extends NexusLabError {
    readonly stage: 'upload' | 'send';
    /** Present after a completed upload, even when sending fails or is cancelled. */
    readonly upload?: UploadFileStreamComplete;

    constructor(stage: 'upload' | 'send', cause: unknown, upload?: UploadFileStreamComplete) {
        super(`Media ${stage} failed${cause instanceof Error ? `: ${cause.message}` : ''}`, {
            cause,
        });
        this.name = 'NexusLabMediaSendError';
        this.stage = stage;
        this.upload = upload;
    }
}

/** Transport-layer failures before a valid OneBot API response is available. */
export class NexusLabTransportError extends NexusLabError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabTransportError';
    }
}

/** The request was cancelled by the caller's AbortSignal. */
export class NexusLabAbortError extends NexusLabTransportError {
    constructor(message = 'NexusLab request aborted', options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabAbortError';
    }
}

/** The request exceeded the configured timeout. */
export class NexusLabTimeoutError extends NexusLabTransportError {
    readonly timeoutMs: number;

    constructor(message: string, timeoutMs: number, options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabTimeoutError';
        this.timeoutMs = timeoutMs;
    }
}

/** The SDK could not establish or keep a connection to NexusLab. */
export class NexusLabConnectionError extends NexusLabTransportError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabConnectionError';
    }
}

/** NexusLab returned a payload that could not be parsed as the expected protocol shape. */
export class NexusLabParseError extends NexusLabTransportError {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options);
        this.name = 'NexusLabParseError';
    }
}

/** A OneBot API response with status failed or a non-zero retcode. */
export class NexusLabApiError<TData = unknown> extends NexusLabError {
    readonly response: ApiResponse<TData>;
    readonly retcode: number;
    readonly wording?: string;

    constructor(response: ApiResponse<TData>) {
        super(response.wording || `NexusLab API failed with retcode ${response.retcode}`);
        this.name = 'NexusLabApiError';
        this.response = response;
        this.retcode = response.retcode;
        this.wording = response.wording;
    }
}

/** Authentication or authorization failure returned by NexusLab. */
export class NexusLabAuthError<TData = unknown> extends NexusLabApiError<TData> {
    constructor(response: ApiResponse<TData>) {
        super(response);
        this.name = 'NexusLabAuthError';
    }
}

export function createNexusLabApiError<TData>(
    response: ApiResponse<TData>,
): NexusLabApiError<TData> {
    return isAuthFailure(response)
        ? new NexusLabAuthError(response)
        : new NexusLabApiError(response);
}

function isAuthFailure(response: ApiResponse<unknown>): boolean {
    return response.retcode === 1401 || response.retcode === 401 || response.retcode === 403;
}
