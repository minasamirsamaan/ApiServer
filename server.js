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
var genRandomString = function(length){
    return crypto.randomBytes(Math.ceil(length/2))
            .toString('hex') /** convert to hexadecimal format */
            .slice(0,length);   /** return required number of characters */
};

var sha512 = function(password, salt){
    var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
    hash.update(password);
    var value = hash.digest('hex');
    console.log(value);
    return {
        salt:salt,
        passwordHash:value

}};
//---------------------------------------------------------------------------------------------------------------------
app.get('/', function(req, res) {
  res.write("Hello, am Mina Samir's Security Api Server");
  res.end();
})
//key_exchange_and_AES-------------------------------------------------------------------------------------------------------------
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

	console.log(buf);
  sharedKey=ecdh.computeSecret(buf);
	//aesCtr = new aesjs.ModeOfOperation.ctr(sharedKey);
    res.json(sharedKey);
})
app.get('/setSharedKey/:shared', function(req, res) {
var buf = new Buffer.from(JSON.parse(req.params.shared));
	aesCtr = new aesjs.ModeOfOperation.ctr(buf);
    res.send("Shared key Ready");
})
//  ****for encryption and decryption you should use set sharedkey route first****
app.get('/decrypt/:bytes', function(req, res) {
var buf=JSON.parse(req.params.bytes);
	var arr = [];
		for(var p in Object.getOwnPropertyNames(buf)) {
		    arr[p] = buf[p];
		}
    console.log('the sharedKey before encryption ::: ' +sharedKey.toString('hex'));
    console.log('these are the encryptedBytes ::: ' +req.params.bytes);

var decryptedBytes = aesCtr.decrypt(arr);
    console.log('these are the decryptedBytes ::: ' +decryptedBytes);
var decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
res.send(decryptedText);

})
app.get('/encrypt/:text', function(req, res) {
var textBytes = aesjs.utils.utf8.toBytes(req.params.text);
var encryptedBytes = aesCtr.encrypt(textBytes);
console.log('the sharedKey before encryption ::: ' +sharedKey.toString('hex'));
console.log('these are the textBytes ::: ' +textBytes);
console.log('these are the encryptedBytes ::: ' +encryptedBytes);
res.send(JSON.stringify(encryptedBytes));

})
//authentication-----------------------------------------------------------------------------------------------------------------

app.get('/salt', function(req, res) {

  res.send(genRandomString(16));
})

app.get('/passwordHash/:salt/:password', function(req, res) {
var passwordData = sha512(req.params.password, req.params.salt);
res.send(passwordData.passwordHash);
})


app.listen(process.env.PORT ||8080, ()=>console.log("ok"))
