import {Frame} from '../types/Frame'
import {UpdateContext} from '../types/UpdateContext'
import {IAnalysisReducer} from '../interfaces/IAnalysisReducer'

/**
 * Fold every frame into a single accumulator — the streaming analogue of Array.reduce. `fold` must
 * return the next accumulator (treat it as immutable); reset() restores the seed.
 */
export function reduceReducer<TResult>(seed: TResult, fold: (accumulator: TResult, frame: Frame, context: UpdateContext) => TResult): IAnalysisReducer<TResult> {
    let accumulator: TResult = seed
    return {
        update(frame: Frame, context: UpdateContext): void {
            accumulator = fold(accumulator, frame, context)
        },
        result(): TResult {
            return accumulator
        },
        reset(): void {
            accumulator = seed
        }
    }
}

/**
 * Group frames by a derived key, folding each group's frames into a per-group value (seeded per
 * group). result() returns a snapshot copy of the group map; reset() clears it.
 */
export function groupByReducer<TKey, TValue>(keyOf: (frame: Frame) => TKey, seed: TValue, fold: (accumulator: TValue, frame: Frame) => TValue): IAnalysisReducer<Map<TKey, TValue>> {
    const groups: Map<TKey, TValue> = new Map<TKey, TValue>()
    return {
        update(frame: Frame): void {
            const key: TKey = keyOf(frame)
            const current: TValue = groups.has(key) ? groups.get(key) as TValue : seed
            groups.set(key, fold(current, frame))
        },
        result(): Map<TKey, TValue> {
            return new Map<TKey, TValue>(groups)
        },
        reset(): void {
            groups.clear()
        }
    }
}
