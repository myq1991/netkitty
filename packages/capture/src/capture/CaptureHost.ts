import {fork} from 'node:child_process'
import path from 'node:path'
import isElectron from 'is-electron'
import type {UtilityProcess} from 'electron'
import {randomInt} from 'crypto'
import {PipeServer} from '../pipe/PipeServer'
import {PipeClientSocket} from '../pipe/PipeClientSocket'
import {IPcapPacketInfo} from '@netkitty/pcap'

export interface ICaptureSessionConfig {
    device: string
    filter: string
    emit: string
    temporaryFilename: string
}

interface ISession {
    config: ICaptureSessionConfig
    onPacket: (info: IPcapPacketInfo) => void
    onCrash: (error: Error) => void
    started: boolean
}

type ForkedProcess = {once: (event: string, listener: () => void) => void, kill?: (signal?: string) => void}

/**
 * Process-wide singleton that hosts every live capture in ONE child process. Each Capture registers a
 * session keyed by a unique id; the host runs one native capture thread per session and streams packets
 * back — tagged by id — over a single multiplexed pipe. Collapsing N captures into 1 process (instead of
 * one forked worker each) is the resource win for multi-interface capture, and if the host crashes it is
 * respawned with every active session re-created, so one bad capture can't take the whole app down.
 */
class CaptureHost {

    #workerModule: string = path.resolve(__dirname, './workers/CaptureHostWorker.js')

    #pipeServer: PipeServer | null = null

    #process: ForkedProcess | null = null

    #socket: PipeClientSocket | null = null

    #connecting: Promise<PipeClientSocket> | null = null

    readonly #sessions: Map<string, ISession> = new Map<string, ISession>()

    #shuttingDown: boolean = false

    public setWorkerModule(module: string): void {
        this.#workerModule = module
    }

    async #ensureHost(): Promise<PipeClientSocket> {
        if (this.#socket) return this.#socket
        if (this.#connecting) return this.#connecting
        this.#connecting = new Promise<PipeClientSocket>((resolve: (socket: PipeClientSocket) => void): void => {
            this.#shuttingDown = false
            const pipeServer: PipeServer = new PipeServer()
            this.#pipeServer = pipeServer
            const hostId: string = `CH_${Date.now().toString(16)}${randomInt(0xffff).toString(16)}`
            pipeServer.once('connect', (socket: PipeClientSocket): void => {
                this.#socket = socket
                socket.on('packet', (payload: {id: string, info: IPcapPacketInfo}): void => {
                    this.#sessions.get(payload.id)?.onPacket(payload.info)
                })
                resolve(socket)
            })
            const env: Record<string, string> = {captureHostId: hostId, socketPath: pipeServer.socketPath}
            if (isElectron()) {
                //Lazy-require electron only inside an Electron runtime (see Capture for the rationale).
                // eslint-disable-next-line @typescript-eslint/no-require-imports
                const {utilityProcess}: {utilityProcess: {fork: (m: string, a: string[], o: {env: Record<string, string>}) => UtilityProcess}} = require('electron')
                this.#process = utilityProcess.fork(this.#workerModule, [], {env: env}) as unknown as ForkedProcess
            } else {
                this.#process = fork(this.#workerModule, [], {env: env}) as unknown as ForkedProcess
            }
            this.#process.once('exit', (): void => void this.#handleHostExit())
        })
        return this.#connecting
    }

    async #handleHostExit(): Promise<void> {
        this.#socket = null
        this.#connecting = null
        this.#process = null
        this.#pipeServer?.dispose()
        this.#pipeServer = null
        //Intentional shutdown, or nothing left to keep alive — do not respawn.
        if (this.#shuttingDown || this.#sessions.size === 0) return
        //Unexpected crash: respawn the host and re-create every session, restarting the active ones.
        const socket: PipeClientSocket = await this.#ensureHost()
        for (const [id, session] of this.#sessions) {
            try {
                await socket.invoke('create', {id: id, ...session.config})
                if (session.started) await socket.invoke('start', {id: id})
            } catch { /* best effort; onCrash still notifies the owner */ }
            session.onCrash(new Error('capture host crashed and was restarted'))
        }
    }

    public async create(id: string, config: ICaptureSessionConfig, onPacket: (info: IPcapPacketInfo) => void, onCrash: (error: Error) => void): Promise<void> {
        const socket: PipeClientSocket = await this.#ensureHost()
        this.#sessions.set(id, {config: config, onPacket: onPacket, onCrash: onCrash, started: false})
        await socket.invoke('create', {id: id, ...config})
    }

    public async start(id: string): Promise<void> {
        const socket: PipeClientSocket = await this.#ensureHost()
        await socket.invoke('start', {id: id})
        const session: ISession | undefined = this.#sessions.get(id)
        if (session) session.started = true
    }

    public async stop(id: string): Promise<void> {
        if (!this.#socket) return
        await this.#socket.invoke('stop', {id: id})
        const session: ISession | undefined = this.#sessions.get(id)
        if (session) session.started = false
    }

    public async count(id: string): Promise<number> {
        if (!this.#socket) return 0
        return this.#socket.invoke('count', {id: id})
    }

    public async setFilter(id: string, filter: string): Promise<void> {
        if (!this.#socket) return
        await this.#socket.invoke('setFilter', {id: id, filter: filter})
        const session: ISession | undefined = this.#sessions.get(id)
        if (session) session.config.filter = filter
    }

    public async destroy(id: string): Promise<void> {
        if (!this.#sessions.has(id)) return
        this.#sessions.delete(id)
        if (this.#socket) {
            try {
                await this.#socket.invoke('destroy', {id: id})
            } catch { /* host may already be gone */ }
        }
        //Last session gone: tear the host process down so it doesn't linger.
        if (this.#sessions.size === 0) await this.#shutdown()
    }

    async #shutdown(): Promise<void> {
        this.#shuttingDown = true
        const socket: PipeClientSocket | null = this.#socket
        const process: ForkedProcess | null = this.#process
        if (socket && process) {
            await new Promise<void>((resolve: () => void): void => {
                const done: () => void = (): void => {
                    clearTimeout(timeout)
                    resolve()
                }
                socket.once('disconnect', done)
                socket.notify('exit')
                const timeout: NodeJS.Timeout = setTimeout((): void => {
                    process.kill?.('SIGINT')
                    resolve()
                }, 10000)
            })
        }
        this.#socket = null
        this.#connecting = null
        this.#process = null
        this.#pipeServer?.dispose()
        this.#pipeServer = null
    }
}

export const captureHost: CaptureHost = new CaptureHost()
