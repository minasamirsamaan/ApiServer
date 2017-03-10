var express = require('express')
var app = express()
//---------------------------------------------------------------------------------------------------------------------
var crypto = require('crypto');
var ecdh = crypto.createECDH('secp256k1');
var clientPublicKey;
var sharedKey;
//ENCRYPTION-----------------------------------------------------------------------------------------------------------
var aesjs = require('aes-js');
var aesCtr;
//---------------------------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.send("I am Mina's Api ECDH Server")
})

app.get('/publicKey', function(req, res) {
ecdh.generateKeys();
var publicKey = ecdh.getPublicKey(null,'compressed');
var privateKey = ecdh.getPrivateKey(null, 'compressed');
  res.send(publicKey)
})

app.get('/sharedKey/:public', function(req, res) {   ecdh.computeSecret(JSON.parse(req.params.public));
})
 
app.listen(process.env.PORT ||8080, ()=>console.log("ok"))

