import {DecodeResult, JSONSchemaProtocol} from '../../schema/JSONSchemaProtocol'

export abstract class BaseProtocol {

    public static get PROTOCOL_NAME(): string {
        return this.name
    }

    /**
     * Current value for previous header ref
     * @constructor
     */
    public static get ID(): number {
        return -1
    }

    /**
     * Ref to previous header field
     * @constructor
     */
    public static get PREV_HEADER_REF(): string {
        return ''
    }

    /**
     * Ref to next header field
     * @constructor
     */
    public static get NEXT_HEADER_REF(): string {
        return ''
    }

    protected readonly protocolConstructorMap: Map<string, (typeof BaseProtocol)>

    public abstract schema: JSONSchemaProtocol

    constructor(protocolConstructorMap: Map<string, (typeof BaseProtocol)>) {
        this.protocolConstructorMap = protocolConstructorMap
    }

    public async schemaEncode() {
        //TODO
    }

    public async schemaDecode(data: Buffer, offset?: number, headers?: DecodeResult[]): Promise<DecodeResult[]> {
        const headerOffset: number = offset ? offset : 0
        const decodeResults: DecodeResult[] = headers ? headers : []
        const value: Record<string, DecodeResult> = {}
        await Promise.all(Object.keys(this.schema.properties!).map((property: string) => {
            const properties: { [p: string]: JSONSchemaProtocol } = (this.schema.properties!) as {
                [p: string]: JSONSchemaProtocol
            }
            return new Promise<void>(async (resolve, reject) => {
                try {
                    value[property] = await properties[property].decode!(data)
                    return resolve()
                } catch (e) {
                    return reject(e)
                }
            })
        }))
        let headerWalkLength: number = 0
        let minOffset: number = Infinity
        Object.keys(value).forEach((key: string): void => {
            value[key].offset += headerOffset
            minOffset = minOffset > value[key].offset ? value[key].offset : minOffset
            const endPos: number = value[key].offset + value[key].length
            headerWalkLength = endPos > headerWalkLength ? endPos : headerWalkLength
        })
        const actualHeaderLength: number = headerWalkLength - headerOffset
        const headerDecodeResult: DecodeResult = {
            offset: minOffset,
            length: actualHeaderLength,
            label: this.constructor['PROTOCOL_NAME'],
            value: value
        }
        const nextData: Buffer = data.subarray(actualHeaderLength)
        decodeResults.push(headerDecodeResult)
        //链接下一层
        if (!this.schema.$nextHeaderRef) return decodeResults
        const nextId: number = headerDecodeResult.value[this.schema.$nextHeaderRef].value
        const nextHeaderRef: string = this.constructor['NEXT_HEADER_REF']
        let nextProtocolConstructor: any
        this.protocolConstructorMap.forEach(protocolConstructor => {
            if (protocolConstructor.ID == nextId && protocolConstructor.PREV_HEADER_REF === nextHeaderRef) {
                nextProtocolConstructor = protocolConstructor
            }
        })
        if (!nextProtocolConstructor) {
            const rawDataConstructor = (this.protocolConstructorMap.get('$RawData')!) as any
            return await new rawDataConstructor(this.protocolConstructorMap).schemaDecode(nextData, headerOffset + actualHeaderLength, decodeResults)
        }
        return await new nextProtocolConstructor(this.protocolConstructorMap).schemaDecode(nextData, headerOffset + actualHeaderLength, decodeResults)
    }
}
