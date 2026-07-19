import {Frame} from '../types/Frame'
import {UpdateContext} from '../types/UpdateContext'

/**
 * A pluggable rolling analysis over the frame stream. Fed every frame (replay backlog first, then
 * live) via update(); result() returns the current snapshot at any time — there is no finalize. A
 * reducer may additionally extend an event emitter to push progress/update notifications of its own.
 */
export interface IAnalysisReducer<TResult> {
    //Optional: protocol-layer ids this reducer needs, so the worker projects only those fields to it.
    readonly needs?: string[]
    //Optional: when true, the reducer only uses the five-tuple (via flowOf) and frame metadata — never
    //deep decoded fields. Replay then feeds it frames synthesized from the index columns, skipping the
    //per-frame re-decode entirely (orders of magnitude faster). Setting it while reading a deep field
    //would give wrong results, so only built-in five-tuple reducers and equivalent user reducers set it.
    readonly indexOnly?: boolean
    update(frame: Frame, context: UpdateContext): void
    result(): TResult
    reset(): void
}
