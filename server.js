var express = require('express')
var app = express()
//---------------------------------------------------------------------------------------------------------------------
var crypto = require('crypto');
var ecdh;
var clientPublicKey;
var sharedKey;
var publicKey;
var privateKey;
//ENCRYPTION-----------------------------------------------------------------------------------------------------------
var aesjs = require('aes-js');
var aesCtr;
//---------------------------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.write("I am Mina's Api ECDH Server");
  res.end();
})
		
app.get('/publicKey', function(req, res) {
	ecdh= crypto.createECDH('secp256k1');
	ecdh.generateKeys();
publicKey = ecdh.getPublicKey(null,'compressed');
privateKey = ecdh.getPrivateKey(null, 'compressed');

  res.json(publicKey);
})
app.get('/privateKey', function(req, res) {

  res.json(privateKey)
})

app.get('/sharedKey/:public', function(req, res) { 
var buf = new Buffer.from(JSON.parse(req.params.public));

	console.log(buf);  sharedKey=ecdh.computeSecret(buf);   
	aesCtr = new aesjs.ModeOfOperation.ctr(sharedKey);
    res.json(sharedKey);
})
app.get('/decrypt/:public', function(req, res) {
var buf=JSON.parse(req.params.public);
var decryptedBytes = aesCtr.decrypt(buf);
res.write(aesjs.utils.utf8.fromBytes(decryptedBytes));

})


 
app.listen(process.env.PORT ||8080, ()=>console.log("ok"))

