import { test } from '@substrate-system/tapzero'
import { EccKeys } from '../src/ecc/index.js'

test('Create a new keypair', async t => {
    const myKeys = await EccKeys.create('ecc')
    t.ok(myKeys, 'should create the keys')
})
