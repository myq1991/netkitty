import {test} from 'node:test'
import assert from 'node:assert'
import {NetKittyError, ErrorCode} from '../../src/index'

test('NetKittyError: is an Error, carries errno/code, name is the class', (): void => {
    const e: NetKittyError = new NetKittyError('boom')
    assert.ok(e instanceof Error, 'is an Error')
    assert.ok(e instanceof NetKittyError, 'is a NetKittyError')
    assert.strictEqual(e.message, 'boom')
    assert.strictEqual(e.name, 'NetKittyError')
    assert.strictEqual(e.errno, 0)
    assert.strictEqual(e.code, 'E_NETKITTY')
})

test('a subclass overrides errno/code and stays instanceof NetKittyError (cross-package catch)', (): void => {
    class DeviceNotFoundError extends NetKittyError {
        public errno: number = ErrorCode.E_DEVICE_NOT_FOUND.errno
        public code: string = ErrorCode.E_DEVICE_NOT_FOUND.code
    }
    const e: DeviceNotFoundError = new DeviceNotFoundError('no such device')
    assert.ok(e instanceof NetKittyError, 'a package subclass is still a NetKittyError — unified catch works')
    assert.ok(e instanceof Error)
    assert.strictEqual(e.name, 'DeviceNotFoundError', 'name is the concrete subclass')
    assert.strictEqual(e.errno, 1000)
    assert.strictEqual(e.code, 'E_DEVICE_NOT_FOUND')
})

test('ErrorCode: every errno is unique', (): void => {
    const errnos: number[] = Object.values(ErrorCode).map((c): number => c.errno)
    assert.strictEqual(new Set(errnos).size, errnos.length, 'errno values are unique across the registry')
})
