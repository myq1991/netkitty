import {GetNodePcapBinding} from './GetNodePcapBinding'
import {inherits} from 'util'
import EventEmitter from 'events'
import {IBindingCapture} from '../interfaces/IBindingCapture'

let BindingCaptureClass: any

export function GetNodePcapBindingCapture(): IBindingCapture {
    if (!BindingCaptureClass) {
        const NodePcapBinding: any = GetNodePcapBinding()
        BindingCaptureClass = NodePcapBinding.Capture
        inherits(BindingCaptureClass, EventEmitter)
    }
    return BindingCaptureClass
}
