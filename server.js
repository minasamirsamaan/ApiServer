//API_Server--------------------------------------------------------------------------------------------------
var express = require('express');
var app = express();
var bodyParser = require('body-parser');
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
var serverRsaKey ="gBEp6sYxb/tezOdhmub+WZIZSVYjd1CHQ589S9a4O8xv6gmk7bZY5wO5LTZ9cbVmJRkISzC1UlHEidip5vzM+SXlQdu4jn43S4MUv7ExGgwpgwK9Ng0iMEtxnAdJF7y41uVbk9JWHdsSSoZpcYplnaLgkvy9bmoDeQUu4VEK060=";

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

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
//Routes-----------------------------------------------------------------------------------------------------

app.get('/', function(req, res) {
  res.write("Hello, am Mina Samir's Bachelor Security Api Server");
  res.end();
})
app.post('/rsaEncrypt', function (req, res) {
  var EncryptionResult = cryptico.encrypt(req.body.text, serverRsaKey);
  res.json(EncryptionResult.cipher);

})
app.get('/rsaEncrypt/:text', function(req, res) {
var EncryptionResult = cryptico.encrypt(req.params.text, serverRsaKey);
res.send(EncryptionResult.cipher);
})

app.get('/getShared/:publicUser', function(req, res) {
var ecdh = crypto.createECDH('secp256k1');
var s = {"type": "Buffer", "data": [167,181,243,38,132,118,233,27,141,157,140,96,4,145,8,60,155,144,73,122,15,37,69,176,32,82,131,232,81,187,6,25]};
var server_pr = new Buffer.from(s);
ecdh.setPrivateKey(server_pr);
var c = req.params.publicUser;
console.log(c);
var sharedKey = ecdh.computeSecret(new Buffer.from(JSON.parse(c)));
res.send(JSON.stringify(sharedKey));

})

app.get('/generateKeys', function(req, res) {
  ecdh= crypto.createECDH('secp256k1');
  ecdh.generateKeys();
  var AesPublicKey = ecdh.getPublicKey(null,'compressed');
  var AesPrivateKey = ecdh.getPrivateKey(null, 'compressed');
  var x ={"type": "Buffer", "data": [3,74,163,143,202,145,179,253,76,91,222,98,121,169,25,92,235,174,45,164,14,124,167,87,37,202,45,207,61,33,22,202,200]}
  var serverAesPublic = new Buffer.from(x);
  var AesSharedKey = ecdh.computeSecret(serverAesPublic);
  res.json({
    AesPublicKey : AesPublicKey,
    AesPrivateKey: AesPrivateKey,
    AesSharedKey:AesSharedKey
  });

})

app.get('/register/:password', function(req, res) {
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
