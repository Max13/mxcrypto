var elixir = require("laravel-elixir");
var gulp = require("gulp");

elixir(function (mix) {
    if (elixir.config.production) {
        mix.browserify("./index.js", "./dist/mxcrypto.min.js");
    } else {
        mix.browserify("./index.js", "./dist/mxcrypto.js");
    }
});
