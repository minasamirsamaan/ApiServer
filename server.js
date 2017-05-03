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
  res.write("Hello, am Mina Samir's Bachelor Security Api Server");
  res.end();
})
app.get('/rsaEncrypt/:serverPublic/:text', function(req, res) {
console.console.log(req.params.serverPublic);
var EncryptionResult = cryptico.encrypt(req.params.text, JSON.parse(req.params.serverPublic));
res.send(EncryptionResult.cipher);
})

app.get('/exchange/:serverAesPublic', function(req, res) {
  ecdh= crypto.createECDH('secp256k1');
  ecdh.generateKeys();
  var AesPublicKey = ecdh.getPublicKey(null,'compressed');
  var AesPrivateKey = ecdh.getPrivateKey(null, 'compressed');
  var serverAesPublic = new Buffer.from(JSON.parse(req.params.serverAesPublic));
  var AesSharedKey = ecdh.computeSecret(serverAesPublic);
  res.json({
    AesPublicKey : AesPublicKey,
    AesPrivateKey: AesPrivateKey,
    AesSharedKey:AesSharedKey
  });

})

app.get('/register/:password/:serverRsaPublic', function(req, res) {
  var salt = genRandomString(16);
  var passwordData = sha512(req.params.password, salt);

  res.json({
    salt: salt,
    hash: passwordData.passwordHash,
  });
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

app.get('/AesDecrypt/:shared/:bytes', function(req, res) {
  var sharedKey = new Buffer.from(JSON.parse(req.params.shared));
  aesCtr = new aesjs.ModeOfOperation.ctr(sharedKey);
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

app.get('/AesEncrypt/:shared/:text', function(req, res) {
  var buf = new Buffer.from(JSON.parse(req.params.shared));
  aesCtr = new aesjs.ModeOfOperation.ctr(buf);
  var text =req.params.text;
  console.log(req.params.text + typeof req.params.text);
var textBytes = aesjs.utils.utf8.toBytes(text.toString());
var encryptedBytes = aesCtr.encrypt(textBytes);

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
