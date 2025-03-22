import {ProtocolJSONSchema} from '../../schema/ProtocolJSONSchema'
import {BaseHeader} from '../abstracts/BaseHeader'
import {CodecModule} from '../types/CodecModule'

export default class IPv4 extends BaseHeader {

    public SCHEMA: ProtocolJSONSchema = {
        properties: {
            version: {
                type: 'integer',
                label: 'Version',
                enum: [4, 6],
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            hdrLen: {
                type: 'integer',
                label: 'Header Length',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            dsfield: {
                type: 'object',
                label: 'Differentiated Services Field',
                properties: {
                    dscp: {
                        type: 'integer',
                        label: 'Differentiated Services Codepoint',
                        decode: (): void => {
                            //TODO
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    ecn: {
                        type: 'integer',
                        label: 'Explicit Congestion Notification',
                        decode: (): void => {
                            //TODO
                        },
                        encode: (): void => {
                            //TODO
                        }
                    }
                }
            },
            length: {
                type: 'integer',
                label: 'Total Length',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            id: {
                type: 'integer',
                label: 'Identification',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            flags: {
                type: 'object',
                label: 'Flags',
                properties: {
                    rb: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Reserved bit',
                        decode: (): void => {
                            //TODO
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    df: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'Don\'t fragment',
                        decode: (): void => {
                            //TODO
                        },
                        encode: (): void => {
                            //TODO
                        }
                    },
                    mf: {
                        type: 'integer',
                        enum: [0, 1],
                        label: 'More fragments',
                        decode: (): void => {
                            //TODO
                        },
                        encode: (): void => {
                            //TODO
                        }
                    }
                }
            },
            fragOffset: {
                type: 'integer',
                minimum: 0,
                maximum: 8191,
                label: 'Fragment Offset',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            ttl: {
                type: 'integer',
                minimum: 0,
                maximum: 255,
                label: 'Time to Live',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            protocol: {
                type: 'integer',
                label: 'Protocol',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            checksum: {
                type: 'integer',
                label: 'Header Checksum',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            sip: {
                type: 'string',
                label: 'Source Address',
                minLength: 7,
                maxLength: 15,
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            dip: {
                type: 'string',
                minLength: 7,
                maxLength: 15,
                label: 'Destination Address',
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            options: {
                type: 'array',
                label: 'Options',
                items: {
                    type: 'number'
                },
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            },
            padding: {
                type: 'array',
                label: 'Padding',
                items: {
                    type: 'number',
                    minimum: 0,
                    maximum: 0
                },
                decode: (): void => {
                    //TODO
                },
                encode: (): void => {
                    //TODO
                }
            }
        }
    }

    public id: string = 'ipv4'

    public name: string = 'IPv4'

    public match(prevCodecModule: CodecModule, prevCodecModules: CodecModule[]): boolean {
        if (!prevCodecModule) return false
        return prevCodecModule.instance.etherType === 0x0800
    }
}
