import {parentPort, MessagePort} from 'node:worker_threads'
import {WorkerEndpoint} from './WorkerEndpoint'
import {NodeFileReadBackend} from '../backends/NodeFileReadBackend'
import {IReadBackend} from '../interfaces/IReadBackend'
import {installAnalysisHandlers} from './AnalysisWorkerCore'

/**
 * node analysis worker entrypoint: a WorkerEndpoint over the worker_threads parent port, and a backend
 * factory that treats the source as a filesystem path. All handler logic lives in AnalysisWorkerCore.
 */
installAnalysisHandlers(
    new WorkerEndpoint(parentPort as MessagePort),
    (source: unknown): IReadBackend => new NodeFileReadBackend(source as string)
)
