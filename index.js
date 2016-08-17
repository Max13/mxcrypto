var mxcrypto = {
    mxcrypto: "1.0.0",
    __: undefined,

    str2ab(str) {
        let bytes = new Uint8Array(str.length);
        for (let i=0, z=str.length; i < z; ++i) {
            bytes[i] = str.charCodeAt(i);
        }
        return bytes.buffer;
    },

    ab2str(ab) {
        return global.String.fromCharCode.apply(null, new Uint8Array(ab));
    },

    str2hex(str) {
        var result = "";

        for (var i=0, z=str.length; i<z; i++) {
            result += ("00" + str.charCodeAt(i).toString(16)).slice(-2);
        }

        return result
    },

    hex2str(hex) {
        var result = "";
        hex = hex.match(/.{2}/g) || [];

        for(var i=0, z=hex.length; i<z; i++) {
            result += global.String.fromCharCode(parseInt(hex[i], 16));
        }

        return result;
    },

    objExtract(obj, props) {
        let newObj = {};

        for (let p in props) {
            if (props[p] in obj) {
                newObj[props[p]] = obj[props[p]];
            }
        }

        return newObj;
    },

    generateAesKey(length = 128, extractable = true) {
        return global.crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: length,
            },
            extractable,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        ).catch((err) => {
            console.error("Error generating AES-GCM key:", err);
        })
    },

    importAesKey(pwd) {
        return global.crypto.subtle.importKey(
            "raw",
            new Uint8Array(pwd),
            {
                name: "AES-GCM",
            },
            false,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        ).catch((err) => {
            console.error("Error importing AES-GCM key:", err);
        });
    },

    generateRsaKeys(extractable = true) {
        return global.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: {name: "SHA-256"},
            },
            extractable,
            ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
        ).catch((err) => {
            console.error("Error generating RSA-OAEP keys:", err);
        });
    },

    exportRsaKeys(rsaKeys, aesKey) {
        if (!(rsaKeys.privateKey instanceof global.CryptoKey)
            || !(rsaKeys.publicKey instanceof global.CryptoKey)
            || !(aesKey instanceof global.CryptoKey)) {
            return global.Promise.reject("rsaKeys must be an RSA keypair (or must be stored)");
        }

        let iv = global.crypto.getRandomValues(new Uint8Array(aesKey.algorithm.length / 8));

        return Promise.all([
            global.crypto.subtle.wrapKey(
                "jwk",
                rsaKeys.privateKey,
                aesKey,
                {
                    name: aesKey.algorithm.name,
                    iv: iv
                }
            ).then((wrappedKey) => {
                return {
                    iv: this.ab2str(iv),
                    key: this.ab2str(wrappedKey)
                };
            }),
            global.crypto.subtle.exportKey(
                "jwk",
                rsaKeys.publicKey
            )
        ]).then((rsaKeys) => {
            return {
                privateKey: rsaKeys[0],
                publicKey: rsaKeys[1]
            };
        }).catch((err) => {
            console.error("Error exporting RSA-OAEP keys:", err);
        });
    },

    importRsaKeys(privateKey = null, aesKey = null, publicKey = null) {
        if (!privateKey.iv && !privateKey.alg) {
            return global.Promise.reject("1st argument must be a private or public key");
        }
        if (privateKey.iv && !(aesKey instanceof global.CryptoKey)) {
            return global.Promise.reject("2nd argument must be a CryptoKey");
        }
        if (publicKey && !publicKey.alg) {
            return global.Promise.reject("3rd argument (if present) must be a public key");
        }

        let importing = [];

        if (privateKey.iv) {    // Private Key
            importing.push(
                global.crypto.subtle.unwrapKey(
                    "jwk",
                    this.str2ab(privateKey.key),
                    aesKey,
                    {
                        name: aesKey.algorithm.name,
                        iv: this.str2ab(privateKey.iv)
                    },
                    {
                        name: "RSA-OAEP",           // TODO: Store in key
                        hash: {name: "SHA-256"}     // TODO: Store in key
                    },
                    false,
                    ["decrypt", "unwrapKey"]
                ).catch((err) => {
                    console.error("Error unwrapping RSA-OAEP private key:", err);
                })
            );
        }

        let key;
        if ((key = privateKey).alg || ((key = publicKey) && key.alg)) {
            importing.push(
                global.crypto.subtle.importKey(
                    "jwk",
                    key,
                    {
                        name: "RSA-OAEP",           // TODO: Get from key
                        hash: {name: "SHA-256"},    // TODO: Get from key
                    },
                    key.ext,
                    key.key_ops
                ).catch((err) => {
                    console.error("Error importing RSA-OAEP public key:", err);
                })
            );
        }

        return Promise.all(
            importing
        ).then((keys) => {
            return {
                privateKey: (keys[0].type == "private" ? keys[0] : null),
                publicKey: (keys[keys.length - 1].type == "public" ? keys[keys.length - 1] : null)
            };
        }).catch((err) => {
            console.error("Error importing RSA-OAEP key pair:", err);
        });
    },

    wrapKey(targetKey, wrappingKey) {
        let wrapOptions = {},
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

        return global.crypto.subtle.wrapKey(
            "jwk",
            targetKey,
            wrappingKey,
            wrapOptions
        ).then((wrappedKey) => {
            let wrappedData = {
                wrapping: this.objExtract(wrapOptions, ["name", "length", "hash", "iv"]),
                wrapped: this.objExtract(targetKey.algorithm, ["name", "length", "hash"]),
                data: this.ab2str(wrappedKey)
            };

            wrappedData.wrapped.usages = targetKey.usages;

            if ("iv" in wrappedData.wrapping) {
                wrappedData.wrapping.iv = this.ab2str(wrappedData.wrapping.iv);
            }

            return wrappedData;
        }).catch((err) => {
            console.error("Error wrapping key:", err);
        });
    },

    unwrapKey(targetKey, unwrappingKey) {
        if ("iv" in targetKey.wrapping) {
            targetKey.wrapping.iv = this.str2ab(targetKey.wrapping.iv);
        }

        return global.crypto.subtle.unwrapKey(
            "jwk",
            this.str2ab(targetKey.data),
            unwrappingKey,
            targetKey.wrapping,
            targetKey.wrapped,
            false,
            targetKey.wrapped.usages
        ).catch((err) => {
            console.error("Error unwrapping key:", err);
        });
    },

    encrypt(cleartext, key) {
        let encryptOptions = {},
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

        return global.crypto.subtle.encrypt(
            encryptOptions,
            key,
            this.str2ab(cleartext)
        ).then((ciphertext) => {
            let cipherData = {
                algo: this.objExtract(encryptOptions, ["name", "length", "hash", "iv"]),
                data: this.ab2str(ciphertext)
            };

            if ("iv" in cipherData.algo) {
                cipherData.algo.iv = this.ab2str(cipherData.algo.iv);
            }

            return cipherData;
        }).catch((err) => {
            console.error("Error encrypting cleartext:", err);
        });
    },

    decrypt(cipherdata, key) {
        if ("iv" in cipherdata.algo) {
            cipherdata.algo.iv = this.str2ab(cipherdata.algo.iv);
        }

        return global.crypto.subtle.decrypt(
            cipherdata.algo,
            key,
            this.str2ab(cipherdata.data)
        ).then((cleartext) => {
            return this.ab2str(cleartext);
        }).catch((err) => {
            console.error("Error decrypting cipherdata:", err);
        });
    },

    init() {
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

    noConflict() {
        if (this.__ === undefined) {
            return;
        }

        global.__ = this.__;
        this.__ = undefined;
    }
};

mxcrypto.init();

if (module && module.exports) module.exports = mxcrypto;
