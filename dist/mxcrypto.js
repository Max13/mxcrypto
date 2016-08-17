(function e(t,n,r){function s(o,u){if(!n[o]){if(!t[o]){var a=typeof require=="function"&&require;if(!u&&a)return a(o,!0);if(i)return i(o,!0);var f=new Error("Cannot find module '"+o+"'");throw f.code="MODULE_NOT_FOUND",f}var l=n[o]={exports:{}};t[o][0].call(l.exports,function(e){var n=t[o][1][e];return s(n?n:e)},l,l.exports,e,t,n,r)}return n[o].exports}var i=typeof require=="function"&&require;for(var o=0;o<r.length;o++)s(r[o]);return s})({1:[function(require,module,exports){
(function (global){
"use strict";

var mxcrypto = {
    mxcrypto: "1.0.0",
    __: undefined,

    str2ab: function str2ab(str) {
        var bytes = new Uint8Array(str.length);
        for (var i = 0, z = str.length; i < z; ++i) {
            bytes[i] = str.charCodeAt(i);
        }
        return bytes.buffer;
    },
    ab2str: function ab2str(ab) {
        return global.String.fromCharCode.apply(null, new Uint8Array(ab));
    },
    str2hex: function str2hex(str) {
        var result = "";

        for (var i = 0, z = str.length; i < z; i++) {
            result += ("00" + str.charCodeAt(i).toString(16)).slice(-2);
        }

        return result;
    },
    hex2str: function hex2str(hex) {
        var result = "";
        hex = hex.match(/.{2}/g) || [];

        for (var i = 0, z = hex.length; i < z; i++) {
            result += global.String.fromCharCode(parseInt(hex[i], 16));
        }

        return result;
    },
    objExtract: function objExtract(obj, props) {
        var newObj = {};

        for (var p in props) {
            if (props[p] in obj) {
                newObj[props[p]] = obj[props[p]];
            }
        }

        return newObj;
    },
    generateAesKey: function generateAesKey() {
        var length = arguments.length <= 0 || arguments[0] === undefined ? 128 : arguments[0];
        var extractable = arguments.length <= 1 || arguments[1] === undefined ? true : arguments[1];

        return global.crypto.subtle.generateKey({
            name: "AES-GCM",
            length: length
        }, extractable, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]).catch(function (err) {
            console.error("Error generating AES-GCM key:", err);
        });
    },
    importAesKey: function importAesKey(pwd) {
        return global.crypto.subtle.importKey("raw", new Uint8Array(pwd), {
            name: "AES-GCM"
        }, false, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]).catch(function (err) {
            console.error("Error importing AES-GCM key:", err);
        });
    },
    generateRsaKeys: function generateRsaKeys() {
        var extractable = arguments.length <= 0 || arguments[0] === undefined ? true : arguments[0];

        return global.crypto.subtle.generateKey({
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" }
        }, extractable, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]).catch(function (err) {
            console.error("Error generating RSA-OAEP keys:", err);
        });
    },
    exportRsaKeys: function exportRsaKeys(rsaKeys, aesKey) {
        var _this = this;

        if (!(rsaKeys.privateKey instanceof global.CryptoKey) || !(rsaKeys.publicKey instanceof global.CryptoKey) || !(aesKey instanceof global.CryptoKey)) {
            return global.Promise.reject("rsaKeys must be an RSA keypair (or must be stored)");
        }

        var iv = global.crypto.getRandomValues(new Uint8Array(aesKey.algorithm.length / 8));

        return Promise.all([global.crypto.subtle.wrapKey("jwk", rsaKeys.privateKey, aesKey, {
            name: aesKey.algorithm.name,
            iv: iv
        }).then(function (wrappedKey) {
            return {
                iv: _this.ab2str(iv),
                key: _this.ab2str(wrappedKey)
            };
        }), global.crypto.subtle.exportKey("jwk", rsaKeys.publicKey)]).then(function (rsaKeys) {
            return {
                privateKey: rsaKeys[0],
                publicKey: rsaKeys[1]
            };
        }).catch(function (err) {
            console.error("Error exporting RSA-OAEP keys:", err);
        });
    },
    importRsaKeys: function importRsaKeys() {
        var privateKey = arguments.length <= 0 || arguments[0] === undefined ? null : arguments[0];
        var aesKey = arguments.length <= 1 || arguments[1] === undefined ? null : arguments[1];
        var publicKey = arguments.length <= 2 || arguments[2] === undefined ? null : arguments[2];

        if (!privateKey.iv && !privateKey.alg) {
            return global.Promise.reject("1st argument must be a private or public key");
        }
        if (privateKey.iv && !(aesKey instanceof global.CryptoKey)) {
            return global.Promise.reject("2nd argument must be a CryptoKey");
        }
        if (publicKey && !publicKey.alg) {
            return global.Promise.reject("3rd argument (if present) must be a public key");
        }

        var importing = [];

        if (privateKey.iv) {
            // Private Key
            importing.push(global.crypto.subtle.unwrapKey("jwk", this.str2ab(privateKey.key), aesKey, {
                name: aesKey.algorithm.name,
                iv: this.str2ab(privateKey.iv)
            }, {
                name: "RSA-OAEP", // TODO: Store in key
                hash: { name: "SHA-256" } // TODO: Store in key
            }, false, ["decrypt", "unwrapKey"]).catch(function (err) {
                console.error("Error unwrapping RSA-OAEP private key:", err);
            }));
        }

        var key = void 0;
        if ((key = privateKey).alg || (key = publicKey) && key.alg) {
            importing.push(global.crypto.subtle.importKey("jwk", key, {
                name: "RSA-OAEP", // TODO: Get from key
                hash: { name: "SHA-256" } }, key.ext, key.key_ops).catch(function (err) {
                console.error("Error importing RSA-OAEP public key:", err);
            }));
        }

        return Promise.all(importing).then(function (keys) {
            return {
                privateKey: keys[0].type == "private" ? keys[0] : null,
                publicKey: keys[keys.length - 1].type == "public" ? keys[keys.length - 1] : null
            };
        }).catch(function (err) {
            console.error("Error importing RSA-OAEP key pair:", err);
        });
    },
    wrapKey: function wrapKey(targetKey, wrappingKey) {
        var _this2 = this;

        var wrapOptions = {},
            iv = null;

        if (wrappingKey.type == "public") {
            wrapOptions = wrappingKey.algorithm;
        } else if (wrappingKey.type == "secret") {
            iv = global.crypto.getRandomValues(new Uint8Array(wrappingKey.algorithm.length / 8));
            wrapOptions = {
                name: wrappingKey.algorithm.name,
                iv: iv
            };
        } else {
            return Promise.reject("wrappingKey not supported (only public or secret)");
        }

        return global.crypto.subtle.wrapKey("jwk", targetKey, wrappingKey, wrapOptions).then(function (wrappedKey) {
            var wrappedData = {
                wrapping: _this2.objExtract(wrapOptions, ["name", "length", "hash", "iv"]),
                wrapped: _this2.objExtract(targetKey.algorithm, ["name", "length", "hash"]),
                data: _this2.ab2str(wrappedKey)
            };

            wrappedData.wrapped.usages = targetKey.usages;

            if ("iv" in wrappedData.wrapping) {
                wrappedData.wrapping.iv = _this2.ab2str(wrappedData.wrapping.iv);
            }

            return wrappedData;
        }).catch(function (err) {
            console.error("Error wrapping key:", err);
        });
    },
    unwrapKey: function unwrapKey(targetKey, unwrappingKey) {
        if ("iv" in targetKey.wrapping) {
            targetKey.wrapping.iv = this.str2ab(targetKey.wrapping.iv);
        }

        return global.crypto.subtle.unwrapKey("jwk", this.str2ab(targetKey.data), unwrappingKey, targetKey.wrapping, targetKey.wrapped, false, targetKey.wrapped.usages).catch(function (err) {
            console.error("Error unwrapping key:", err);
        });
    },
    encrypt: function encrypt(cleartext, key) {
        var _this3 = this;

        var encryptOptions = {},
            iv = null;

        if (key.type == "public") {
            encryptOptions = key.algorithm;
        } else if (key.type == "secret") {
            iv = global.crypto.getRandomValues(new Uint8Array(key.algorithm.length / 8));
            encryptOptions = {
                name: key.algorithm.name,
                iv: iv
            };
        } else {
            return Promise.reject("key not supported (only public or secret)");
        }

        return global.crypto.subtle.encrypt(encryptOptions, key, this.str2ab(cleartext)).then(function (ciphertext) {
            var cipherData = {
                algo: _this3.objExtract(encryptOptions, ["name", "length", "hash", "iv"]),
                data: _this3.ab2str(ciphertext)
            };

            if ("iv" in cipherData.algo) {
                cipherData.algo.iv = _this3.ab2str(cipherData.algo.iv);
            }

            return cipherData;
        }).catch(function (err) {
            console.error("Error encrypting cleartext:", err);
        });
    },
    decrypt: function decrypt(cipherdata, key) {
        var _this4 = this;

        if ("iv" in cipherdata.algo) {
            cipherdata.algo.iv = this.str2ab(cipherdata.algo.iv);
        }

        return global.crypto.subtle.decrypt(cipherdata.algo, key, this.str2ab(cipherdata.data)).then(function (cleartext) {
            return _this4.ab2str(cleartext);
        }).catch(function (err) {
            console.error("Error decrypting cipherdata:", err);
        });
    },
    init: function init() {
        if (!global) {
            throw new Error("A global/window object is needed");
        }

        if (!global.crypto || !global.crypto.subtle) {
            console.error("WebCrypto isn't available");
        }

        if (global.__ && global.__.mxcrypto === undefined) {
            this.__ = global.__;
        }
        global.__ = this;
    },
    noConflict: function noConflict() {
        if (this.__ === undefined) {
            return;
        }

        global.__ = this.__;
        this.__ = undefined;
    }
};

mxcrypto.init();

if (module && module.exports) module.exports = mxcrypto;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}]},{},[1]);

//# sourceMappingURL=mxcrypto.js.map
