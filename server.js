var express = require('express')
var app = express()
//---------------------------------------------------------------------------------------------------------------------
var crypto = require('crypto');
var ecdh = crypto.createECDH('secp256k1');
ecdh.generateKeys();
console.log(ecdh.getPublicKey());
var publicKey = ecdh.getPublicKey(null,'compressed');
var privateKey = ecdh.getPrivateKey(null, 'compressed');
var clientPublicKey;
var sharedKey;
//ENCRYPTION-----------------------------------------------------------------------------------------------------------
var aesjs = require('aes-js');
var aesCtr;
//---------------------------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.json("publicKey")
})
app.get('/publicKey', function(req, res) {
  res.json(publicKey)
})
app.get('/sharedKey', function(req, res) {
  res.json(publicKey)
})
 
app.listen(process.env.PORT ||8080, ()=>console.log("ok"))
