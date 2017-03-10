var express = require('express')
var app = express()
//---------------------------------------------------------------------------------------------------------------------
var crypto = require('crypto');
var ecdh = crypto.createECDH('secp256k1');
var clientPublicKey;
var sharedKey;
var keys=ecdh.generateKeys();
var publicKey = ecdh.getPublicKey(null,'compressed');
var privateKey = ecdh.getPrivateKey(null, 'compressed');
console.log(publicKey);
//ENCRYPTION-----------------------------------------------------------------------------------------------------------
var aesjs = require('aes-js');
var aesCtr;
//---------------------------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.send("I am Mina's Api ECDH Server")
})
		
app.get('/publicKey', function(req, res) {

  res.json(publicKey);
})
app.get('/privateKey', function(req, res) {

  res.json(privateKey)
})

app.get('/sharedKey/:public', function(req, res) { 
var buf = new Buffer.from(JSON.parse(req.params.public));

	console.log(buf);  sharedKey=ecdh.computeSecret(buf);   console.log(sharedKey);
res.json(sharedKey);
})

 
app.listen(process.env.PORT ||8080, ()=>console.log("ok"))

