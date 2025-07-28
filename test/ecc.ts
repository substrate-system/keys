import { test } from '@substrate-system/tapzero'
import { EccCurve, KeyUse } from '../src/types'
import { create } from '../src/ecc/index.js'

test('Create a new keypair', t => {
    const myKeys = create(EccCurve.P_521, KeyUse.Sign)
    t.ok(myKeys, 'should create the keys')
})
