import {GetCaptureBinding} from './GetCaptureBinding'
import {inherits} from 'util'
import EventEmitter from 'events'
import {IBindingCapture} from './interfaces/IBindingCapture'

let BindingCaptureClass: any

export function GetCaptureBindingClass(): IBindingCapture {
    if (!BindingCaptureClass) {
        const binding: any = GetCaptureBinding()
        BindingCaptureClass = binding.NetKittyCapture
        inherits(BindingCaptureClass, EventEmitter)
    }
    return BindingCaptureClass
}
