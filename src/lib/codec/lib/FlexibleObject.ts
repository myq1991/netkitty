export class FlexibleObject {

    readonly #parent: FlexibleObject | undefined

    readonly #paths: string[]

    #data: any

    #undefined: boolean = true

    #markFlexibleObjectDefined(): void {
        if (!this.#undefined) return
        this.#undefined = false
        if (this.#parent) this.#parent.#markFlexibleObjectDefined()
    }

    constructor(data?: object, parent?: FlexibleObject, paths?: string[]) {
        this.#parent = parent
        this.#data = {}
        this.#paths = paths ? paths : []
        if (data !== undefined) this.setValue(data)
        return new Proxy(this, {
            get: (target: FlexibleObject, p: string): any => {
                if (this[p]) return (...args: any[]): any => (this[p] as any)(...args)
                if (target.#data[p] === undefined) target.#data[p] = new FlexibleObject(target.#data[p], this, [...this.#paths, p])
                return target.#data[p]
            },
            set: (target: FlexibleObject, p: string, newValue: any): boolean => {
                return false
            }
        })
    }

    /**
     * Set object node value
     * @param value
     */
    // @ts-ignore
    public setValue(value: any): void {
        if (typeof value === 'object' && !Array.isArray(value)) {
            Object.keys(value).forEach(key => {
                this.#data[key] = new FlexibleObject(this.#data[key], this, [...this.#paths, key])
                this.#data[key].setValue(value[key])
            })
        } else {
            this.#data = value
        }
        this.#markFlexibleObjectDefined()
    }

    /**
     * Get object node value
     */
    // @ts-ignore
    public getValue(): any {
        if (this.#undefined) return undefined
        if (typeof this.#data === 'object' && !Array.isArray(this.#data)) {
            const dumpObject: object = {}
            Object.keys(this.#data).forEach((key: string): void => {
                const dumpResult: any = this.#data[key].getValue()
                if (dumpResult === undefined) return
                dumpObject[key] = dumpResult
            })
            return dumpObject
        } else {
            return this.#undefined ? undefined : this.#data
        }
    }

    /**
     * Is current object's value undefined
     */
    // @ts-ignore
    public isUndefined(): boolean {
        return this.#undefined
    }

    /**
     * Get current object path
     */
    // @ts-ignore
    public getPath(): string {
        return this.#paths.join('.')
    }

    [p: string]: FlexibleObject
}
