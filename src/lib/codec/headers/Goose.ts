import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'
import TLV from 'node-tlv'
import {
    HexToFloat32,
    HexToInt16,
    HexToInt32,
    HexToInt64,
    HexToInt8,
    HexToUInt16,
    HexToUInt32,
    HexToUInt8
} from '../lib/HexHelper'

type AllDataItem = {
    dataType: string
    value: any
}

export default class Goose extends BaseHeader {

    protected TLVInstance: TLV

    protected TLVChild: TLV[]

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            appid: {
                type: 'integer',
                minimum: 0,
                maximum: 0x3fff,
                decode: (): void => {
                    this.instance.appid = parseInt(this.readBytes(0, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let APPID: number = parseInt(this.instance.appid.toString())
                    APPID = APPID ? APPID : 0
                    this.writeBytes(0, Buffer.from(APPID.toString(16).padStart(4, '0'), 'hex'))
                }
            },
            length: {
                type: 'integer',
                decode: (): void => {
                    this.instance.length = parseInt(this.readBytes(2, 2).toString('hex'), 16)
                },
                encode: (): void => {
                    let length: number = parseInt(this.instance.length.toString())
                    length = length ? length : 0
                    this.writeBytes(2, Buffer.from(length.toString(16).padStart(4, '0'), 'hex'))
                }
            },
            reserved1: {
                type: 'object',
                decode: (): void => {
                    this.instance.reserved1 = {}
                },
                properties: {
                    simulated: {
                        type: 'boolean',
                        decode: (): void => {
                            this.instance.reserved1['simulated'] = !!this.readBits(4, 2, 0, 1)
                        },
                        encode: (): void => {
                            const simulated: boolean = !!this.instance.reserved1['simulated']
                            this.writeBits(4, 2, 0, 1, simulated ? 1 : 0)
                        }
                    },
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 32767,
                        decode: (): void => {
                            this.instance.reserved1['reserved'] = this.readBits(4, 2, 1, 16)
                        },
                        encode: (): void => {
                            let reserved: number = parseInt(this.instance.reserved1['reserved'].toString())
                            reserved = reserved ? reserved : 0
                            this.writeBits(4, 2, 1, 16, reserved)
                        }
                    }
                }
            },
            reserved2: {
                type: 'object',
                decode: (): void => {
                    this.instance.reserved2 = {}
                },
                properties: {
                    reserved: {
                        type: 'number',
                        minimum: 0,
                        maximum: 65535,
                        decode: (): void => {
                            this.instance.reserved2['reserved'] = this.readBits(4, 2, 0, 16)
                        },
                        encode: (): void => {
                            let reserved: number = parseInt(this.instance.reserved2['reserved'].toString())
                            reserved = reserved ? reserved : 0
                            this.writeBits(4, 2, 0, 16, reserved)
                        }
                    }
                }
            },
            pdu: {
                type: 'object',
                decode: (): void => {
                    const buffer: Buffer = this.readBytes(8, (this.instance.length as number) - 8)
                    this.TLVInstance = TLV.parse(buffer)
                    this.TLVChild = this.TLVInstance.getChild()
                    this.instance.pdu = {}
                },
                encode: (): void => {
                    //TODO
                },
                properties: {
                    gocbRef: {
                        type: 'string',
                        decode: (): void => {
                            this.instance.pdu['gocbRef'] = this.TLVChild.find(tlv => tlv.getTag('number') === 0x80)?.getValue('buffer').toString()
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    timeAllowedtoLive: {
                        type: 'number',
                        decode: (): void => {
                            const timeAllowedtoLiveString: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x81)?.getValue('hex')
                            if (timeAllowedtoLiveString) this.instance.pdu['timeAllowedtoLive'] = parseInt(timeAllowedtoLiveString, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    datSet: {
                        type: 'string',
                        decode: (): void => {
                            this.instance.pdu['datSet'] = this.TLVChild.find(tlv => tlv.getTag('number') === 0x82)?.getValue('buffer').toString()
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    goID: {
                        type: 'string',
                        decode: (): void => {
                            this.instance.pdu['goID'] = this.TLVChild.find(tlv => tlv.getTag('number') === 0x83)?.getValue('buffer').toString()
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    t: {
                        type: 'integer',
                        decode: (): void => {
                            const tStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x84)?.getValue('hex')
                            if (tStr) this.instance.pdu['t'] = parseInt(tStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    stNum: {
                        type: 'integer',
                        decode: (): void => {
                            const stNumStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x85)?.getValue('hex')
                            if (stNumStr) this.instance.pdu['stNum'] = parseInt(stNumStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    sqNum: {
                        type: 'integer',
                        decode: (): void => {
                            const sqNumStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x86)?.getValue('hex')
                            if (sqNumStr) this.instance.pdu['sqNum'] = parseInt(sqNumStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    simulation: {
                        type: 'boolean',
                        decode: (): void => {
                            const simulationStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x87)?.getValue('hex')
                            if (simulationStr) this.instance.pdu['simulation'] = !!parseInt(simulationStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    confRev: {
                        type: 'integer',
                        decode: (): void => {
                            const confRevStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x88)?.getValue('hex')
                            if (confRevStr) this.instance.pdu['confRev'] = parseInt(confRevStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    ndsCom: {
                        type: 'boolean',
                        decode: (): void => {
                            const ndsComStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x89)?.getValue('hex')
                            if (ndsComStr) this.instance.pdu['ndsCom'] = !!parseInt(ndsComStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    numDatSetEntries: {
                        type: 'integer',
                        decode: (): void => {
                            const numDatSetEntriesStr: string | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0x8A)?.getValue('hex')
                            if (numDatSetEntriesStr) this.instance.pdu['numDatSetEntries'] = parseInt(numDatSetEntriesStr, 16)
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    allData: {
                        type: 'array',
                        items: {
                            type: 'object',
                            properties: {
                                dataType: {
                                    type: 'string',
                                    enum: [
                                        'Boolean',
                                        'INT8',
                                        'INT16',
                                        'INT32',
                                        'INT64',
                                        'INT8U',
                                        'INT16U',
                                        'INT32U',
                                        'FLOAT32',
                                        'CODED-ENUM',
                                        'OCTET-STRING',
                                        'VISIBLE-STRING',
                                        'TimeStamp',
                                        'Quality'
                                    ]
                                },
                                value: {
                                    type: 'string'
                                }
                            }
                        },
                        /**
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         * | Data types according to IEC 61850-7-2 | ASN.1 Tag for Data | ASN.1 Length      | Comments                                                                                                                                           |
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         * | Boolean                               | 0x83               |         1         | 8 Bit set to 0 FALSE; anything else = TRUE                                                                                                         |
                         * | INT8                                  | 0x85               |         2         | 8 Bit Big Endian; signed                                                                                                                           |
                         * | INT16                                 | 0x85               |         3         | 16 Bit Big Endian; signed                                                                                                                          |
                         * | INT32                                 | 0x85               |         5         | 32 Bit Big Endian; signed                                                                                                                          |
                         * | INT64                                 | 0x85               |         9         | 64Bit Big Endian; signed                                                                                                                           |
                         * | INT8U                                 | 0x86               |         2         | 8 Bit Big Endian; unsigned                                                                                                                         |
                         * | INT16U                                | 0x86               |         3         | 16 Bit Big Endian; unsigned                                                                                                                        |
                         * | INT24U                                | -                  |         -         | Not used                                                                                                                                           |
                         * | INT32U                                | 0x86               |         5         | 32 Bit Big Endian; unsigned                                                                                                                        |
                         * | FLOAT32                               | 0x87               |         4         | 32 Bit IEEE Floating Point (IEEE 754)                                                                                                              |
                         * | CODED-ENUM                            | 0x84               |         2         | Bit-string; depending on CODED ENUM definition – most of the time, can be encoded with 2 bytes (1st Byte = number of unused bit, 2nd Byte = Value) |
                         * | OCTET-STRING                          | 0x89               |         20        | 20 Bytes ASCII Text, Null terminated                                                                                                               |
                         * | VISIBLE-STRING                        | 0x8a               |         35        | 35 Bytes ASCII Text, Null terminated                                                                                                               |
                         * | TimeStamp                             | 0x91               |         8         | 64 Bit TimeStamp as defined in 8.1.3.7 IEC 6                                                                                                       |
                         * | Quality                               | 0x84               |         3         | Bit-string                                                                                                                                         |
                         * +-----------------------------------+-------------------+-------------------+---------------------------------------------------------------------------------------------------------------------------------------------------------+
                         */
                        decode: (): void => {
                            const allDataTLV: TLV | undefined = this.TLVChild.find(tlv => tlv.getTag('number') === 0xAB)
                            const dataTLVs: TLV[] = allDataTLV ? allDataTLV.getChild() : []
                            const allData: AllDataItem[] = []
                            dataTLVs.forEach((dataTLV: TLV): void => {
                                const length: number = dataTLV.getLength('number')
                                const value: Buffer = dataTLV.getValue('buffer')
                                const dataItem: AllDataItem = {
                                    dataType: '',
                                    value: null
                                }
                                switch (dataTLV.getTag('number')) {
                                    case 0x83: {
                                        dataItem.dataType = 'Boolean'
                                        dataItem.value = String(!!parseInt(value.toString('hex'), 16))
                                    }
                                        break
                                    case 0x84: {
                                        switch (length) {
                                            case 2: {
                                                dataItem.dataType = 'CODED-ENUM'
                                                dataItem.value = parseInt(value.toString('hex'), 16).toString()
                                            }
                                                break
                                            case 3: {
                                                dataItem.dataType = 'Quality'
                                                dataItem.value = parseInt(value.toString('hex'), 16).toString(2).padStart(24, '0')
                                            }
                                                break
                                        }
                                    }
                                        break
                                    case 0x85: {
                                        switch (length) {
                                            case 2: {
                                                dataItem.dataType = 'INT8'
                                                dataItem.value = HexToInt8(value.toString('hex')).toString()
                                            }
                                                break
                                            case 3: {
                                                dataItem.dataType = 'INT16'
                                                dataItem.value = HexToInt16(value.toString('hex')).toString()
                                            }
                                                break
                                            case 5: {
                                                dataItem.dataType = 'INT32'
                                                dataItem.value = HexToInt32(value.toString('hex')).toString()
                                            }
                                                break
                                            case 9: {
                                                dataItem.dataType = 'INT64'
                                                dataItem.value = HexToInt64(value.toString('hex')).toString()
                                            }
                                                break
                                        }
                                    }
                                        break
                                    case 0x86: {
                                        switch (length) {
                                            case 2: {
                                                dataItem.dataType = 'INT8U'
                                                dataItem.value = HexToUInt8(value.toString('hex')).toString()
                                            }
                                                break
                                            case 3: {
                                                dataItem.dataType = 'INT16U'
                                                dataItem.value = HexToUInt16(value.toString('hex')).toString()
                                            }
                                                break
                                            case 5: {
                                                dataItem.dataType = 'INT32U'
                                                dataItem.value = HexToUInt32(value.toString('hex')).toString()
                                            }
                                                break
                                        }
                                    }
                                        break
                                    case 0x87: {
                                        dataItem.dataType = 'FLOAT32'
                                        dataItem.value = HexToFloat32(value.toString('hex')).toString()
                                    }
                                        break
                                    case 0x89: {
                                        dataItem.dataType = 'OCTET-STRING'
                                        dataItem.value = value.toString('ascii')
                                    }
                                        break
                                    case 0x8a: {
                                        dataItem.dataType = 'VISIBLE-STRING'
                                        dataItem.value = value.toString('ascii')
                                    }
                                        break
                                    case 0x91: {
                                        dataItem.dataType = 'TimeStamp'
                                        dataItem.value = parseInt(value.toString('hex'), 16).toString()
                                    }
                                        break
                                }
                                if (!dataItem.dataType) return
                                allData.push(dataItem)
                            })
                            this.instance.pdu['allData'] = allData
                        },
                        encode: (): void => {
                            //TODO
                        }
                    }
                }
            }
        }
    }

    public id: string = 'goose'

    public name: string = 'GOOSE'

    public match(prevCodecModule: CodecModule, prevCodecModules: CodecModule[]): boolean {
        if (!prevCodecModule) return false
        return prevCodecModule.instance.etherType === '0x88b8'
    }
}
