import { type FunctionComponent, render } from 'preact'
import { html } from 'htm/preact'
import { EccKeys } from '../src/ecc/index.js'
import Debug from '@substrate-system/debug'
const debug = Debug()

const keys = await EccKeys.create()

debug('keys', keys)

const Example:FunctionComponent<unknown> = function () {
    return html`<div>hello</div>`
}

render(html`<${Example} />`, document.getElementById('root')!)
