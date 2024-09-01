'use strict'

import ASN1 from '../src/index.js'
import Enc from '@root/encoding'
// import Enc from '../src/hex.js'
// const Enc = require('@root/encoding')
// const PEM = require('@root/pem')
import PEM from '@root/pem'

// 1.2.840.10045.3.1.7
// prime256v1 (ANSI X9.62 named elliptic curve)
const OBJ_ID_EC_256 = '06 08 2A8648CE3D030107'

const jwk = {
    crv: 'P-256',
    d: 'LImWxqqTHbP3LHQfqscDSUzf_uNePGqf9U6ETEcO5Ho',
    kty: 'EC',
    x: 'vdjQ3T6VBX82LIKDzepYgRsz3HgRwp83yPuonu6vqos',
    y: 'IUkEXtAMnppnV1A19sE2bJhUo4WPbq6EYgWxma4oGyg',
    kid: 'MnfJYyS9W5gUjrJLdn8ePMzik8ZJz2qc-VZmKOs_oCw'
}
const d = Enc.base64ToHex(jwk.d)
const x = Enc.base64ToHex(jwk.x)
const y = Enc.base64ToHex(jwk.y)

const der = Enc.hexToBuf(
    ASN1.Any(
        '30', // Sequence
        ASN1.UInt('01'), // Integer (Version 1)
        ASN1.Any('04', d), // Octet String
        ASN1.Any('A0', OBJ_ID_EC_256), // [0] Object ID
        ASN1.Any(
            'A1', // [1] Embedded EC/ASN1 public key
            ASN1.BitStr('04' + x + y)
        )
    )
)

const pem1 = PEM.packBlock({
    type: 'EC PRIVATE KEY',
    bytes: der
})

const expected = [
    '-----BEGIN EC PRIVATE KEY-----',
    'MHcCAQEEICyJlsaqkx2z9yx0H6rHA0lM3/7jXjxqn/VOhExHDuR6oAoGCCqGSM49',
    'AwEHoUQDQgAEvdjQ3T6VBX82LIKDzepYgRsz3HgRwp83yPuonu6vqoshSQRe0Aye',
    'mmdXUDX2wTZsmFSjhY9uroRiBbGZrigbKA==',
    '-----END EC PRIVATE KEY-----'
].join('\n')

if (pem1 !== expected) {
    throw new Error('Did not correctly Cascade pack EC P-256 JWK to DER')
} else {
    console.info('PASS: packed cascaded ASN1')
}

// Mix and match hex ints, hex strings, and byte arrays
const asn1Arr = [
    '30', // Sequence
    [
        [0x02, '01'], // Integer (Version 1)
        [0x04, Buffer.from(d, 'hex')], // Octet String
        ['a0', OBJ_ID_EC_256], // [0] Object ID
        [
            0xa1, // [1] Embedded EC/ASN1 public key
            ASN1.BitStr('04' + x + y)
        ]
    ]
]

const der2 = ASN1.pack(asn1Arr)
const pem2 = PEM.packBlock({
    type: 'EC PRIVATE KEY',
    bytes: der2
})

if (pem2 !== expected) {
    console.log(pem2)
    console.log(expected)
    throw new Error('Did not correctly Array pack EC P-256 JWK to DER')
} else {
    console.info('PASS: packed array-style ASN1')
}

const block = PEM.parseBlock(expected)
const arr1 = ASN1.parse({ der: block.bytes })
// console.log(JSON.stringify(arr1));
const arr2 = ASN1.parse({ der: block.bytes, verbose: false, json: false })
const obj3 = ASN1.parse({ der: block.bytes, verbose: true, json: true })
// console.log(obj3);

function eq (b1, b2) {
    if (b1.byteLength !== b2.byteLength) {
        return false
    }
    return b1.every(function (b, i) {
        return b === b2[i]
    })
}

if (!eq(block.bytes, ASN1.pack(arr1))) {
    throw new Error('packing hex array resulted in different bytes')
} else {
    console.log('PASS: packs parsed (hex) array')
}

if (!eq(block.bytes, ASN1.pack(arr2))) {
    throw new Error('packing array with bytes resulted in different bytes')
} else {
    console.log('PASS: packs parsed array (with bytes)')
}

if (!eq(block.bytes, ASN1.pack(obj3))) {
    console.log(block.bytes.toString('hex'))
    console.log(ASN1.pack(obj3))
    throw new Error('packing verbose object resulted in different bytes')
} else {
    console.log('PASS: packs parsed verbose object')
}

if (block.bytes.toString('hex') !== ASN1.pack(obj3, { json: true })) {
    throw new Error('packing to hex resulted in different bytes')
} else {
    console.log('PASS: packs as hex when json: true')
}
