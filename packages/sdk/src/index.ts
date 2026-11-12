export { NEXUSLAB_ACTIONS, isNexusLabAction } from './actions.js';
export type { NexusLabKnownAction } from './actions.js';
export { NexusLabApiClient } from './client/api-client.js';
export { createHttpClient, NexusLabHttpClient } from './client/http-client.js';
export type { NexusLabHttpClientOptions } from './client/http-client.js';
export { createWebSocketClient, NexusLabWebSocketClient } from './client/websocket-client.js';
export {
    createNexusLabApiError,
    NexusLabAbortError,
    NexusLabApiError,
    NexusLabAuthError,
    NexusLabConnectionError,
    NexusLabError,
    NexusLabMediaSendError,
    NexusLabParseError,
    NexusLabTimeoutError,
    NexusLabTransportError,
} from './errors.js';
export {
    createEventContext,
    isBotStatusEvent,
    isGroupMessageEvent,
    isMessageEvent,
    isMetaEvent,
    isNoticeEvent,
    isPrivateMessageEvent,
    isRequestEvent,
    matchCommand,
    noticeType,
    requestType,
} from './events/index.js';
export {
    at,
    atAll,
    br,
    chain,
    contact,
    escapeCqParam,
    escapeCqText,
    face,
    forward,
    fromCQString,
    image,
    json,
    location,
    message,
    MessageChain,
    music,
    node,
    normalizeMessage,
    parseSegments,
    poke,
    quoteMessage,
    raw,
    record,
    reply,
    share,
    text,
    toCQString,
    video,
    xml,
} from './messages/index.js';

export type {
    EventWaitOptions,
    ReconnectOptions,
    NexusLabWebSocketClientOptions,
    NexusLabWebSocketEvents,
    WebSocketCloseInfo,
    WebSocketConstructor,
} from './client/websocket-client.js';

export type {
    CommandHandler,
    CommandMatch,
    CommandOptions,
    EventHandler,
    EventMiddleware,
    EventNext,
    EventPredicate,
    MaybePromise,
    RequestDecisionOptions,
    NexusLabEventContext,
    NexusLabEventContextWithQuote,
} from './events/index.js';

export type * from './types/index.js';
