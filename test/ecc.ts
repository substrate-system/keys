import { test } from '@substrate-system/tapzero'
import { EccKeys } from '../src/ecc/index.js'

test('Create a new keypair', async t => {
    const myKeys = await EccKeys.create('ecc')
    t.ok(myKeys, 'should create the keys')
})

test('done', () => {
    // @ts-expect-error dev
    window.testsFinished = true
})
