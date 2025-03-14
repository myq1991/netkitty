import EventEmitter from 'events'
import {IBindingCaptureOptions} from './IBindingCaptureOptions'

export interface IBindingCapture extends EventEmitter {

    new(options: IBindingCaptureOptions): IBindingCapture

    start(): void

    stop(): void

    setFilter(filter: string): void

    send(packet: Buffer): void

    on(eventName: 'data', callback: (data: Buffer, sec: number, usec: number) => void): this

    on(eventName: string, listener: (...args: any[]) => void): this

    off(eventName: 'data', callback: (data: Buffer, sec: number, usec: number) => void): this

    off(eventName: string, listener: (...args: any[]) => void): this

    removeAllListeners(eventName?: 'data'): this

    removeAllListeners(eventName?: string): this
}
