import { Enc } from './hex.js'

//
// Packer
//

export const ASN1Packer = {
    // Almost every ASN.1 type that's important for CSR
    // can be represented generically with only a few rules.
    Any (...rest) {
        const args = Array.prototype.slice.call(rest)
        const typ = args.shift()
        const str = args
            .join('')
            .replace(/\s+/g, '')
            .toLowerCase()
        let len = str.length / 2
        let lenlen = 0
        let hex = typ

        if (typeof hex === 'number') {
            hex = Enc.numToHex(hex)
        }

        // We can't have an odd number of hex chars
        if (len !== Math.round(len)) {
            throw new Error('invalid hex')
        }

        // The first byte of any ASN.1 sequence is the type (Sequence, Integer, etc)
        // The second byte is either the size of the value, or the size of its size

        // 1. If the second byte is < 0x80 (128) it is considered the size
        // 2. If it is > 0x80 then it describes the number of bytes of the size
        //    ex: 0x82 means the next 2 bytes describe the size of the value
        // 3. The special case of exactly 0x80 is "indefinite" length (to end-of-file)

        if (len > 127) {
            lenlen += 1
            while (len > 255) {
                lenlen += 1
                len = len >> 8
            }
        }

        if (lenlen) {
            hex += Enc.numToHex(0x80 + lenlen)
        }
        return hex + Enc.numToHex(str.length / 2) + str
    },

    // The Integer type has some special rules
    UInt (...args) {
        let str = Array.prototype.slice.call(args).join('')
        const first = parseInt(str.slice(0, 2), 16)

        // If the first byte is 0x80 or greater, the number is considered negative
        // Therefore we add a '00' prefix if the 0x80 bit is set
        if (0x80 & first) {
            str = '00' + str
        }

        return ASN1Packer.Any('02', str)
    },

    // The Bit String type also has a special rule
    BitStr (...args) {
        const str = Array.prototype.slice.call(args).join('')
        // '00' is a mask of how many bits of the next byte to ignore
        return ASN1Packer.Any('03', '00' + str)
    },

    _toArray (next, opts) {
        const typ = opts.json ? Enc.numToHex(next.type) : next.type
        let val = next.value
        if (val) {
            if (typeof val !== 'string' && opts.json) {
                val = Enc.bufToHex(val)
            }
            return [typ, val]
        }
        return [
            typ,
            next.children.map(function (child) {
                return ASN1Packer._toArray(child, opts)
            })
        ]
    },

    _pack (arr) {
        let typ = arr[0]
        if (typeof arr[0] === 'number') {
            typ = Enc.numToHex(arr[0])
        }
        let str = ''
        if (Array.isArray(arr[1])) {
            arr[1].forEach(function (a) {
                str += ASN1Packer._pack(a)
            })
        } else if (typeof arr[1] === 'string') {
            str = arr[1]
        } else if (arr[1].byteLength) {
            str = Enc.bufToHex(arr[1])
        } else {
            throw new Error('unexpected array')
        }
        if (typ === '03') {
            return ASN1Packer.BitStr(str)
        } else if (typ === '02') {
            return ASN1Packer.UInt(str)
        } else {
            return ASN1Packer.Any(typ, str)
        }
    },

    // TODO should this return a buffer?
    pack (asn1, opts) {
        if (!opts) {
            opts = {}
        }
        if (!Array.isArray(asn1)) {
            asn1 = ASN1Packer._toArray(asn1, { json: true })
        }
        const result = ASN1Packer._pack(asn1)
        if (opts.json) {
            return result
        }
        return Enc.hexToBuf(result)
    }
}
