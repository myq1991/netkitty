import {Worker} from 'node:worker_threads'
import path from 'node:path'
import {NodeWorkerChannel} from './NodeWorkerChannel'
import {IWorkerChannel} from '../interfaces/IWorkerChannel'

/**
 * node channel factory: spawns the analysis worker (sibling compiled .js) and wraps it in a
 * NodeWorkerChannel. Loaded lazily by the Analysis facade so the facade itself never statically
 * imports worker_threads and stays environment-agnostic.
 */
export function spawnNodeAnalysisChannel(): IWorkerChannel {
    const worker: Worker = new Worker(path.resolve(__dirname, 'analysisWorker.js'))
    return new NodeWorkerChannel(worker)
}
