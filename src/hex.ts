export const Enc = {
    // to Binary String
    bufToBin (buf):string {
        let bin = ''
        // cannot use .map() because Uint8Array would return only 0s
        buf.forEach(function (ch) {
            bin += String.fromCharCode(ch)
        })

        return bin
    },

    hexToBuf (hex:string) {
        const arr:number[] = []
        hex.match(/.{2}/g)!.forEach((h) => {
            arr.push(parseInt(h, 16))
        })

        return typeof Uint8Array !== 'undefined' ? new Uint8Array(arr) : arr
    },

    strToBin (str:string) {
        // Note: TextEncoder might be faster (or it might be slower, I don't know),
        // but it doesn't solve the double-utf8 problem and MS Edge still has
        //   users without it
        const escstr = encodeURIComponent(str)

        // replace any uri escape sequence, such as %0A,
        // with binary escape, such as 0x0A
        const binstr = escstr.replace(/%([0-9A-F]{2})/g, function (_, p1) {
            return String.fromCharCode(Number('0x' + p1))
        })

        return binstr
    },

    binToBuf  (bin) {
        const arr = bin.split('').map(function (ch) {
            return ch.charCodeAt(0)
        })

        return typeof Uint8Array !== 'undefined' ? new Uint8Array(arr) : arr
    },

    strToBuf (str:string) {
        return Enc.binToBuf(Enc.strToBin(str))
    },

    // to Unicode String
    binToStr (binstr:string) {
        const escstr = binstr.replace(/(.)/g, function (m, p) {
            let code = p
                .charCodeAt(0)
                .toString(16)
                .toUpperCase()
            if (code.length < 2) {
                code = '0' + code
            }
            return '%' + code
        })

        return decodeURIComponent(escstr)
    },

    bufToStr (buf) {
        return Enc.binToStr(Enc.bufToBin(buf))
    },

    bufToHex (u8:Uint8Array) {
        const hex:string[] = []
        let i, h:string
        const len = u8.byteLength || u8.length

        for (i = 0; i < len; i += 1) {
            h = u8[i].toString(16)
            if (h.length !== 2) {
                h = '0' + h
            }
            hex.push(h)
        }

        return hex.join('').toLowerCase()
    },

    numToHex (_d:number):string {
        const d = _d.toString(16)
        if (d.length % 2) {
            return '0' + d
        }
        return d
    }
}
