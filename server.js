//API_Server--------------------------------------------------------------------------------------------------
var express = require('express');
var app = express();
//ECDH--------------------------------------------------------------------------------------------------------
var crypto = require('crypto');
var ecdh;
var clientPublicKey;
var sharedKey;
var publicKey;
var privateKey;
//AES_Encryption----------------------------------------------------------------------------------------------
var aesjs = require('aes-js');
var aesCtr;
//RSA_Encryption----------------------------------------------------------------------------------------------
var cryptico = require('cryptico');
//Salt_&_Nonce------------------------------------------------------------------------------------------------
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};
//SHA512------------------------------------------------------------------------------------------------------
var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    console.log(value);
    return {
        salt:salt,
        passwordHash:value
           }
};
//Routes-----------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.write("Hello, am Mina Samir's Security Api Server");
  res.end();
})

app.get('/register/:password', function(req, res) {
	ecdh= crypto.createECDH('secp256k1');
	ecdh.generateKeys();
  var AesPublicKey = ecdh.getPublicKey(null,'compressed');
  var AesPrivateKey = ecdh.getPrivateKey(null, 'compressed');
  var salt = genRandomString(16);
  var passwordData = sha512(req.params.password, salt);
  var RsaPrivate = cryptico.generateRSAKey(req.params.password, 1024);
  var RsaPublic = cryptico.publicKeyString(rsaKeys);
  res.json({
    salt: salt,
    hash: passwordData.passwordHash,
    AesPublicKey: AesPublicKey,
    AesPrivateKey: AesPrivateKey,
    RsaPublic: RsaPublic,
    RsaPrivate: RsaPrivate
  });
})

app.get('/sharedKey/:serverPublic/:userPrivate', function(req, res) {
  var serverPublic = new Buffer.from(JSON.parse(req.params.serverPublic));
  var userPrivate = new Buffer.from(JSON.parse(req.params.userPrivate));
  console.console.log(userPrivate);
  ecdh.setPrivateKey(userPrivate);
  sharedKey=ecdh.computeSecret(serverPublic);
  res.send(JSON.stringify(sharedKey));
})

app.get('/publicKey', function(req, res) {
	ecdh= crypto.createECDH('secp256k1');
	ecdh.generateKeys();
  publicKey = ecdh.getPublicKey(null,'compressed');
  privateKey = ecdh.getPrivateKey(null, 'compressed');
  res.send(JSON.stringify(publicKey));
})

app.get('/privateKey', function(req, res) {
  res.send(JSON.stringify(privateKey));
})

//        ****for encryption and decryption you should use set sharedkey route first****

app.get('/setSharedKey/:shared', function(req, res) {
  var buf = new Buffer.from(JSON.parse(req.params.shared));
  aesCtr = new aesjs.ModeOfOperation.ctr(buf);
  res.send("Shared key Ready");
})

app.get('/decrypt/:bytes', function(req, res) {
  var buf=JSON.parse(req.params.bytes);
  var arr = [];
  for(var p in Object.getOwnPropertyNames(buf)) {
  arr[p] = buf[p];}
  console.log('the sharedKey before encryption ::: ' +sharedKey.toString('hex'));
  console.log('these are the encryptedBytes ::: ' +req.params.bytes);
  var decryptedBytes = aesCtr.decrypt(arr);
  console.log('these are the decryptedBytes ::: ' +decryptedBytes);
  var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  res.send(decryptedText);
})

app.get('/encrypt/:shared/:text', function(req, res) {
  var buf = new Buffer.from(JSON.parse(req.params.shared));
  aesCtr = new aesjs.ModeOfOperation.ctr(buf);
var textBytes = aesjs.utils.utf8.toBytes(req.params.text);
var encryptedBytes = aesCtr.encrypt(textBytes);
console.log('the sharedKey before encryption ::: ' +sharedKey.toString('hex'));
console.log('these are the textBytes ::: ' +textBytes);
console.log('these are the encryptedBytes ::: ' +encryptedBytes);
res.send(JSON.stringify(encryptedBytes));
})

//authentication----------------------------------------------------------------------------------------------

app.get('/salt', function(req, res) {
  res.send(genRandomString(16));
})

app.get('/nonce', function(req, res) {
  res.send(genRandomString(32));
})

app.get('/time', function(req, res) {
  var timeStamp = Date.now();
  res.json(timeStamp);
})

app.get('/passwordHash/:salt/:password', function(req, res) {
  var passwordData = sha512(req.params.password, req.params.salt);
  res.send(passwordData.passwordHash);
})

app.listen(process.env.PORT ||8080, ()=>console.log("ok"))


// app.get('/sharedKey/:public', function(req, res) {
// var buf = new Buffer.from(JSON.parse(req.params.public));
//
// 	console.log(buf);
//   sharedKey=ecdh.computeSecret(buf);
// 	//aesCtr = new aesjs.ModeOfOperation.ctr(sharedKey);
//     res.send(JSON.stringify(sharedKey));
// })
