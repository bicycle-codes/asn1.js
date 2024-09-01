'use strict'

const ASN1 = module.exports
const packer = require('./packer.js')
const parser = require('./parser.js')
Object.keys(parser).forEach(function (key) {
    ASN1[key] = parser[key]
})
Object.keys(packer).forEach(function (key) {
    ASN1[key] = packer[key]
})
