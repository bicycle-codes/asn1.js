import { ASN1Packer } from './packer'
import { ASN1Parser } from './parser'

export * from './packer'
export * from './parser'

export const ASN1 = {
    ...ASN1Packer,
    ...ASN1Parser
}

export default ASN1
