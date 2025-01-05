const CryptoJS = require("crypto-js");

class WXBizMsgCrypt {
    #AppID = undefined;
    #AesKey = undefined;
    #AesIV = undefined;
    static #StrBase = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    constructor(aesKey, appid) {
        if (!aesKey || !appid) {
            throw new Error("invalid AesKey or appid");
        }
        this.#AppID = appid;
        this.#AesKey = CryptoJS.enc.Base64.parse(aesKey + "=");
        this.#AesIV = this.#AesKey.clone();
        this.#AesIV.sigBytes = 16;
    }

    static randStr(size = 16, rule) {
        if (!rule) {
            rule = WXBizMsgCrypt.#StrBase;
        }
        let result = "";
        for (let i = 0; i < size; i++) {
            result += rule.charAt(Math.floor(Math.random() * rule.length));
        }
        return result;
    }

    static sha1(...args) {
        const sortedArgs = args.sort().join("");
        return CryptoJS.SHA1(sortedArgs).toString(CryptoJS.enc.Hex);
    }

    #str_to_uint8(str) {
        const encoder = new TextEncoder();
        return encoder.encode(str);
    }

    #uint8_to_str(arr) {
        const decoder = new TextDecoder();
        return decoder.decode(arr);
    }

    #int_to_uint8(num) {
        const arr = new Uint8Array(4);
        for (let i = 4 - 1; i >= 0; i--) {
            arr[i] = num & 0xFF;
            num >>>= 8;
        }
        return arr;
    }

    #uint8_to_int(arr) {
        let result = 0;
        for (let i = 0; i < 4; i++) {
            result = (result << 8) | arr[i];
        }
        return result;
    }

    #unint8_concat(...uint8s) {
        let totalLength = 0;
        for (const arr of uint8s) {
            totalLength += arr.length;
        }
        const result = new Uint8Array(totalLength);
        let offset = 0;
        for (const arr of uint8s) {
            result.set(arr, offset);
            offset += arr.length;
        }
        return result;
    }

    #word_to_uint8(word) {
        return new Uint8Array(word.words.flatMap(w => [
            (w >>> 24) & 0xFF,
            (w >>> 16) & 0xFF,
            (w >>> 8) & 0xFF,
            w & 0xFF
        ]).slice(0, word.sigBytes));
    }

    encrypt(text) {
        const random = WXBizMsgCrypt.randStr(),
            randomBytes = this.#str_to_uint8(random),
            textBytes = this.#str_to_uint8(text),
            lengthBytes = this.#int_to_uint8(textBytes.length),
            appidBytes = this.#str_to_uint8(this.#AppID);

        const combinedBytes = this.#unint8_concat(randomBytes, lengthBytes, textBytes, appidBytes);
        const wordArray = CryptoJS.lib.WordArray.create(combinedBytes);
        const encrypted = CryptoJS.AES.encrypt(wordArray, this.#AesKey, {
            iv: this.#AesIV,
            mode: CryptoJS.mode.CBC,
            padding: CryptoJS.pad.Pkcs7
        });
        return encrypted.toString();
    }

    decrypt(text) {
        try {
            const decoded = CryptoJS.enc.Base64.parse(text);
            const decrypted = CryptoJS.AES.decrypt({ ciphertext: decoded }, this.#AesKey, {
                iv: this.#AesIV,
                mode: CryptoJS.mode.CBC,
                padding: CryptoJS.pad.Pkcs7
            });
            const uint8Array = this.#word_to_uint8(decrypted);
            if (uint8Array.length < 20) {
                throw new Error("Invalid decrypted message");
            }
            const contentLen = this.#uint8_to_int(uint8Array.subarray(16, 20));
            if (contentLen > uint8Array.length - 20) {
                throw new Error("Invalid decrypted message length");
            }
            const msg = this.#uint8_to_str(uint8Array.subarray(20, 20 + contentLen));
            const appid = this.#uint8_to_str(uint8Array.subarray(20 + contentLen));
            if (appid !== this.#AppID) {
                throw new Error("Invalid appid");
            }
            return msg;
        } catch (e) {
            throw new Error("AES decrypt error:" + e);
        }
    }
}

module.exports = WXBizMsgCrypt;