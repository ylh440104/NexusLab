import type {
    OneBotBotStatusEvent,
    OneBotGroupMessageEvent,
    OneBotMessageEvent,
    OneBotMetaEvent,
    OneBotNoticeEvent,
    OneBotPrivateMessageEvent,
    OneBotRequestEvent,
    NexusLabEvent,
} from '../types/index.js';
import type { EventPredicate } from './types.js';

export function isMessageEvent(event: NexusLabEvent): event is OneBotMessageEvent {
    return (
        (event.post_type === 'message' || event.post_type === 'message_sent') &&
        (event.message_type === 'private' || event.message_type === 'group')
    );
}

export function isPrivateMessageEvent(event: NexusLabEvent): event is OneBotPrivateMessageEvent {
    return isMessageEvent(event) && event.message_type === 'private';
}

export function isGroupMessageEvent(event: NexusLabEvent): event is OneBotGroupMessageEvent {
    return isMessageEvent(event) && event.message_type === 'group';
}

export function isNoticeEvent(event: NexusLabEvent): event is OneBotNoticeEvent {
    return event.post_type === 'notice' && typeof event.notice_type === 'string';
}

export function isBotStatusEvent(event: NexusLabEvent): event is OneBotBotStatusEvent {
    return (
        isNoticeEvent(event) &&
        event.notice_type === 'bot_status' &&
        (event.sub_type === 'online' || event.sub_type === 'offline') &&
        typeof event.user_id === 'number'
    );
}

export function isRequestEvent(event: NexusLabEvent): event is OneBotRequestEvent {
    return (
        event.post_type === 'request' &&
        typeof event.request_type === 'string' &&
        typeof event.flag === 'string'
    );
}

export function isMetaEvent(event: NexusLabEvent): event is OneBotMetaEvent {
    return event.post_type === 'meta_event' && typeof event.meta_event_type === 'string';
}

export function noticeType(type: string): EventPredicate<OneBotNoticeEvent> {
    return (event): event is OneBotNoticeEvent =>
        isNoticeEvent(event) && event.notice_type === type;
}

export function requestType(type: string): EventPredicate<OneBotRequestEvent> {
    return (event): event is OneBotRequestEvent =>
        isRequestEvent(event) && event.request_type === type;
}
