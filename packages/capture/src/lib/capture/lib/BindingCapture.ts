import {IBindingCapture} from '../interfaces/IBindingCapture'
import {GetCaptureBindingClass} from './GetCaptureBindingClass'
import {IBindingCaptureOptions} from '../interfaces/IBindingCaptureOptions'

const BindingCaptureClass: IBindingCapture = GetCaptureBindingClass()

export class BindingCapture extends BindingCaptureClass {

    constructor(options: IBindingCaptureOptions) {
        super(options)
    }

    public start(): void {
        super.start()
    }

    public stop(): void {
        super.stop()
    }

    public setFilter(filter: string): void {
        super.setFilter(filter)
    }

    public on(eventName: 'data', callback: (data: Buffer, sec: number, usec: number) => void): this
    public on(eventName: string, listener: (...args: any[]) => void): this {
        super.on(eventName, listener)
        return this
    }

    public off(eventName: 'data', callback: (data: Buffer, sec: number, usec: number) => void): this
    public off(eventName: string, listener: (...args: any[]) => void): this {
        super.off(eventName, listener)
        return this
    }

    public removeAllListeners(eventName?: 'data'): this
    public removeAllListeners(eventName?: string): this {
        super.removeAllListeners(eventName)
        return this
    }
}
