QUnit.test("Initialization", function (assert) {
    assert.ok(window.mxcrypto.__ === undefined, "No global __ were previously defined");
    assert.deepEqual(window.__, window.mxcrypto, "__ is defined as mxcrypto");

    window.mxcrypto.init();
    assert.ok(window.mxcrypto.__ === undefined, "Detects it's already __");
    assert.deepEqual(window.__, window.mxcrypto, "__ is still mxcrypto");

    window.__ = document;
    window.mxcrypto.init();
    assert.deepEqual(window.mxcrypto.__, document, "Has __ backup");
    assert.deepEqual(window.__, window.mxcrypto, "__ is still mxcrypto");

    window.mxcrypto.noConflict();
    assert.ok(window.mxcrypto.__ === undefined, "Doesn't have __ backup anymore");
    assert.deepEqual(window.__, document, "__ is correctly restored");
});

QUnit.module("Helpers", function () {
    QUnit.test("objExtract", function (assert) {
        var obj = {
            a: 1,
            b: 2,
            c: 3,
            d: 4
        };

        assert.deepEqual(window.mxcrypto.objExtract(obj, ["b", "d"]), {b: 2, d: 4});
    });
});

QUnit.module("Symmetric helpers", function () {
    QUnit.module("AES", function () {
        var lastKey;

        QUnit.test("Generate not extractable", function (assert) {
            var done = assert.async();

            window.mxcrypto.generateAesKey(128, false)
            .then(function (key) {
                lastKey = key;
                assert.ok(key instanceof window.CryptoKey, "CryptoKey generated");
                assert.equal(key.algorithm.length, 128, "Correct length");
                assert.notOk(key.extractable, "Not extractable");
                assert.equal(key.type, "secret", "Correct type");
                done();
            });
        });

        QUnit.test("Generate extractable", function (assert) {
            var done = assert.async();

            window.mxcrypto.generateAesKey(128, true)
            .then(function (key) {
                assert.ok(key instanceof window.CryptoKey, "CryptoKey generated");
                assert.equal(key.algorithm.length, 128, "Correct length");
                assert.ok(key.extractable, "Extractable");
                assert.equal(key.type, "secret", "Correct type");
                done();
            });
        });
    });
});
