import {Capture} from '../lib/nodepcap/Capture'
import {BindingCapture} from '../lib/nodepcap/lib/BindingCapture'
import {GetNetworkInterfaces} from '../lib/nodepcap/lib/GetNetworkInterfaces'

// const bc = new BindingCapture({iface: 'en0'})
// bc.on('data', console.log)
// bc.start()

console.log(GetNetworkInterfaces())
