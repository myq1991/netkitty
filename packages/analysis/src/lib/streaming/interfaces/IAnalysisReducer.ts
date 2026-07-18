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
    update(frame: Frame, context: UpdateContext): void
    result(): TResult
    reset(): void
}
