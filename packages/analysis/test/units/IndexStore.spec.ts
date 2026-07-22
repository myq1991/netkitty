import {test} from 'node:test'
import assert from 'node:assert'
import {ColumnarIndexStore} from '../../src/stores/ColumnarIndexStore'
import {FrameIndexRecord} from '../../src/types/FrameIndexRecord'

//Build a record whose fields are all derived from a seed, so assertions are exact. append() ignores
//the `index` field (it assigns the global frame number itself), so seed it with a sentinel.
function rec(seed: number): FrameIndexRecord {
    return {
        index: -1,
        fileOffset: seed * 1000,
        capturedLength: seed + 10,
        originalLength: seed + 20,
        timestamp: 1000 + seed,
        protocolId: seed % 60000,
        conversationHash: seed * 7,
        directionForward: seed % 2
    }
}

test('index store: append returns monotonic frame numbers and get round-trips fields', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(4)
    assert.strictEqual(store.append(rec(0)), 0)
    assert.strictEqual(store.append(rec(1)), 1)
    assert.strictEqual(store.append(rec(2)), 2)
    assert.strictEqual(store.count(), 3)
    assert.deepStrictEqual(store.get(1), {
        index: 1, fileOffset: 1000, capturedLength: 11, originalLength: 21,
        timestamp: 1001, protocolId: 1, conversationHash: 7, directionForward: 1
    })
})

test('index store: get out of range returns null', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(4)
    store.append(rec(0))
    assert.strictEqual(store.get(-1), null)
    assert.strictEqual(store.get(1), null)
})

test('index store: range is half-open [from, to) and clamps', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(4)
    for (let i: number = 0; i < 5; i++) store.append(rec(i))
    const rows: FrameIndexRecord[] = store.range(1, 3)
    assert.deepStrictEqual(rows.map((r: FrameIndexRecord): number => r.index), [1, 2])
    assert.deepStrictEqual(store.range(3, 100).map((r: FrameIndexRecord): number => r.index), [3, 4])
})

test('index store: scan returns frame numbers matching a predicate', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(4)
    for (let i: number = 0; i < 6; i++) store.append(rec(i))
    const even: number[] = store.scan((r: FrameIndexRecord): boolean => r.conversationHash % 2 === 0)
    assert.deepStrictEqual(even, [0, 2, 4])
})

test('index store: grows past initial capacity without corruption', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(2)
    for (let i: number = 0; i < 1000; i++) assert.strictEqual(store.append(rec(i)), i)
    assert.strictEqual(store.count(), 1000)
    assert.strictEqual(store.get(999)!.fileOffset, 999000)
    assert.strictEqual(store.get(500)!.timestamp, 1500)
})

test('index store: evictOldest drops the front, keeps global frame numbers stable', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(8)
    for (let i: number = 0; i < 5; i++) store.append(rec(i))
    store.evictOldest(2)
    assert.strictEqual(store.count(), 3)
    assert.strictEqual(store.firstIndex(), 2)
    assert.strictEqual(store.get(0), null, 'evicted frame is gone')
    assert.strictEqual(store.get(1), null, 'evicted frame is gone')
    assert.strictEqual(store.get(2)!.fileOffset, 2000, 'surviving frame keeps its number and fields')
    assert.strictEqual(store.get(4)!.fileOffset, 4000)
    assert.deepStrictEqual(store.range(0, 100).map((r: FrameIndexRecord): number => r.index), [2, 3, 4])
    //Appends after eviction keep counting up from where we were.
    assert.strictEqual(store.append(rec(9)), 5)
})

test('index store: clear resets length and base', (): void => {
    const store: ColumnarIndexStore = new ColumnarIndexStore(4)
    for (let i: number = 0; i < 3; i++) store.append(rec(i))
    store.evictOldest(1)
    store.clear()
    assert.strictEqual(store.count(), 0)
    assert.strictEqual(store.firstIndex(), 0)
    assert.strictEqual(store.append(rec(0)), 0)
})
