import {test} from 'node:test'
import assert from 'node:assert'
import os from 'node:os'
import {list} from '../../src/index'
import {INetworkInterfaceInfo} from '../../src/interfaces/INetworkInterfaceInfo'

test('list: every interface has the expected structure', (): void => {
    const ifaces: INetworkInterfaceInfo[] = list()
    assert.ok(Array.isArray(ifaces))
    assert.ok(ifaces.length > 0, 'at least one interface')
    for (const iface of ifaces) {
        assert.strictEqual(typeof iface.name, 'string')
        assert.strictEqual(typeof iface.mac, 'string')
        assert.strictEqual(iface.mac, iface.mac.toLowerCase(), 'mac is lower-cased')
        assert.strictEqual(typeof iface.up, 'boolean')
        assert.strictEqual(typeof iface.mtu, 'number')
        assert.strictEqual(typeof iface.description, 'string')
        assert.ok(Array.isArray(iface.addresses))
        for (const address of iface.addresses) {
            assert.ok(address.family === 'ipv4' || address.family === 'ipv6', `family ${address.family}`)
            assert.strictEqual(typeof address.address, 'string')
            assert.strictEqual(typeof address.netmask, 'string')
        }
        for (const counters of [iface.rx, iface.tx]) {
            assert.strictEqual(typeof counters.bytes, 'number')
            assert.strictEqual(typeof counters.packets, 'number')
            assert.strictEqual(typeof counters.errors, 'number')
            assert.strictEqual(typeof counters.dropped, 'number')
        }
    }
})

test('list: is sorted by name', (): void => {
    const names: string[] = list().map((iface: INetworkInterfaceInfo): string => iface.name)
    const sorted: string[] = [...names].sort((a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0))
    assert.deepStrictEqual(names, sorted)
})

test('list: is a superset of os.networkInterfaces() (also lists down / address-less interfaces)', (): void => {
    const names: Set<string> = new Set<string>(list().map((iface: INetworkInterfaceInfo): string => iface.name))
    //os.networkInterfaces() only returns interfaces that are up and have an address; list() must include
    //at least all of those, plus the down / address-less ones it omits.
    for (const osName of Object.keys(os.networkInterfaces())) {
        assert.ok(names.has(osName), `list() includes os interface ${osName}`)
    }
})
