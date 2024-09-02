import { ASN1Packer } from './packer.js'
import { ASN1Parser } from './parser.js'

export * from './packer.js'
export * from './parser.js'

export const ASN1 = {
    ...ASN1Packer,
    ...ASN1Parser
}

export default ASN1
