import type { BridgeContext as BaseBridgeContext } from '@nexuslab/protocol/bridge-context';
import type { ApiHub } from './apis';

export interface BridgeContext extends BaseBridgeContext {
    readonly apis: ApiHub;
}
export type { UploadedFileMeta } from '@nexuslab/protocol/bridge-context';
