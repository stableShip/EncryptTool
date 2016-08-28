var co = require("co");
var Promise = require("bluebird");
var fs = require("fs");
fs = Promise.promisifyAll(fs);
var path = require("path");
var config = {};

config.getPrivateKey = function () {
    return co(function* (){
        var privateKey =yield fs.readFileAsync(path.join(__dirname, "./rsa_key/private.pem"));
        return privateKey;
    })
};

config.getPublicKey = function () {
    return co(function* (){
        var publicKey = yield fs.readFileAsync(path.join(__dirname, "./rsa_key/public.pub"));
        return publicKey;
    })
};


module.exports = config;

