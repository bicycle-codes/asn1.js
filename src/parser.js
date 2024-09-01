// Copyright 2018 AJ ONeal. All rights reserved
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
'use strict'

const ASN1 = module.exports
const Enc = require('@root/encoding/hex')

//
// Parser
//

// Although I've only seen 9 max in https certificates themselves,
// but each domain list could have up to 100
ASN1.ELOOPN = 102
ASN1.ELOOP =
	'uASN1.js Error: iterated over ' +
	ASN1.ELOOPN +
	'+ elements (probably a malformed file)'
// I've seen https certificates go 29 deep
ASN1.EDEEPN = 60
ASN1.EDEEP =
	'uASN1.js Error: element nested ' +
	ASN1.EDEEPN +
	'+ layers deep (probably a malformed file)'
// Container Types are Sequence 0x30, Container Array? (0xA0, 0xA1)
// Value Types are Boolean 0x01, Integer 0x02, Null 0x05, Object ID 0x06, String 0x0C, 0x16, 0x13, 0x1e Value Array? (0x82)
// Bit String (0x03) and Octet String (0x04) may be values or containers
// Sometimes Bit String is used as a container (RSA Pub Spki)
ASN1.CTYPES = [0x30, 0x31, 0xa0, 0xa1]
ASN1.VTYPES = [0x01, 0x02, 0x05, 0x06, 0x0c, 0x82]
ASN1.parseVerbose = function parseAsn1Helper (buf, opts) {
    if (!opts) {
        opts = {}
    }
    // var ws = '  ';
    function parseAsn1 (buf, depth, eager) {
        if (depth.length >= ASN1.EDEEPN) {
            throw new Error(ASN1.EDEEP)
        }

        let index = 2 // we know, at minimum, data starts after type (0) and lengthSize (1)
        const asn1 = { type: buf[0], lengthSize: 0, length: buf[1] }
        let child
        let iters = 0
        let adjust = 0
        let adjustedLen

        // Determine how many bytes the length uses, and what it is
        if (0x80 & asn1.length) {
            asn1.lengthSize = 0x7f & asn1.length
            // I think that buf->hex->int solves the problem of Endianness... not sure
            asn1.length = parseInt(
                Enc.bufToHex(buf.slice(index, index + asn1.lengthSize)),
                16
            )
            index += asn1.lengthSize
        }

        // High-order bit Integers have a leading 0x00 to signify that they are positive.
        // Bit Streams use the first byte to signify padding, which x.509 doesn't use.
        if (buf[index] === 0x00 && (asn1.type === 0x02 || asn1.type === 0x03)) {
            // However, 0x00 on its own is a valid number
            if (asn1.length > 1) {
                index += 1
                adjust = -1
            }
        }
        adjustedLen = asn1.length + adjust

        // console.warn(depth.join(ws) + '0x' + Enc.numToHex(asn1.type), index, 'len:', asn1.length, asn1);

        function parseChildren (eager) {
            asn1.children = []
            // console.warn('1 len:', (2 + asn1.lengthSize + asn1.length), 'idx:', index, 'clen:', 0);
            while (
                iters < ASN1.ELOOPN &&
				index < 2 + asn1.length + asn1.lengthSize
            ) {
                iters += 1
                depth.length += 1
                child = parseAsn1(
                    buf.slice(index, index + adjustedLen),
                    depth,
                    eager
                )
                depth.length -= 1
                // The numbers don't match up exactly and I don't remember why...
                // probably something with adjustedLen or some such, but the tests pass
                index += 2 + child.lengthSize + child.length
                // console.warn('2 len:', (2 + asn1.lengthSize + asn1.length), 'idx:', index, 'clen:', (2 + child.lengthSize + child.length));
                if (index > 2 + asn1.lengthSize + asn1.length) {
                    // if (!eager) {
                    //	console.error(JSON.stringify(asn1, ASN1._replacer, 2));
                    // }
                    throw new Error(
                        'Parse error: child value length (' +
							child.length +
							') is greater than remaining parent length (' +
							(asn1.length - index) +
							' = ' +
							asn1.length +
							' - ' +
							index +
							')'
                    )
                }
                asn1.children.push(child)
                // console.warn(depth.join(ws) + '0x' + Enc.numToHex(asn1.type), index, 'len:', asn1.length, asn1);
            }
            if (index !== 2 + asn1.lengthSize + asn1.length) {
                // console.warn('index:', index, 'length:', (2 + asn1.lengthSize + asn1.length));
                throw new Error('premature end-of-file')
            }
            if (iters >= ASN1.ELOOPN) {
                throw new Error(ASN1.ELOOP)
            }

            delete asn1.value
            return asn1
        }

        // Recurse into types that are _always_ containers
        if (ASN1.CTYPES.indexOf(asn1.type) !== -1) {
            return parseChildren(eager)
        }

        // Return types that are _always_ values
        asn1.value = buf.slice(index, index + adjustedLen)
        if (opts.json) {
            asn1.value = Enc.bufToHex(asn1.value)
        }
        if (ASN1.VTYPES.indexOf(asn1.type) !== -1) {
            return asn1
        }

        // For ambigious / unknown types, recurse and return on failure
        // (and return child array size to zero)
        try {
            return parseChildren(true)
        } catch (e) {
            asn1.children.length = 0
            return asn1
        }
    }

    const asn1 = parseAsn1(buf, [])
    const len = buf.byteLength || buf.length
    if (len !== 2 + asn1.lengthSize + asn1.length) {
        throw new Error(
            'Length of buffer does not match length of ASN.1 sequence.'
        )
    }
    return asn1
}
ASN1._toArray = function toArray (next, opts) {
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
            return toArray(child, opts)
        })
    ]
}
ASN1.parse = function (opts) {
    const opts2 = { json: opts.json !== false }
    const verbose = ASN1.parseVerbose(opts.der, opts2)
    if (opts.verbose) {
        return verbose
    }
    return ASN1._toArray(verbose, opts2)
}
ASN1._replacer = function (k, v) {
    if (k === 'type') {
        return '0x' + Enc.numToHex(v)
    }
    if (v && k === 'value') {
        return '0x' + Enc.bufToHex(v.data || v)
    }
    return v
}
