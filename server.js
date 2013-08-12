//==============================================================================
//require('buffertools');
var crypto = require('crypto');

// Crypto globals
var AES_BLOCK_SIZE = 16;  // 16 Bytes - default AES block size
var SIG_SIZE = 32; // HMAC-256 - 256 bits aka 32 bytes

//------------------------------------------------------------------------------
function generate_key_string(key_size) {
    // Create a key with size 'key_size' for AES (in bytes) & HMAC (in bytes)
    var key = crypto.randomBytes((key_size / 8) + SIG_SIZE);
    
    // Encode the key in base64
    var key_b64 = key.toString('base64');

    return key_b64;
}
//------------------------------------------------------------------------------
function extract_keys(key_b64, key_size) {
    // Decode base64 to get binary key
    var key = new Buffer(key_b64, 'base64').toString('binary');
    
    // Extract AES & HMAC keys (both are 256 bits aka 32 bytes)
    var aes_key = key.substring(0,(key.length - SIG_SIZE));
    var hmac_key = key.substring((key.length - SIG_SIZE));

    return [aes_key, hmac_key];
}
//------------------------------------------------------------------------------
function encrypt(aes_key, hmac_key, data) {
    // Create an initialization vector using the default AES block size
    var iv = crypto.randomBytes(AES_BLOCK_SIZE);

    // Create AES-256 cipher
    var cipher = crypto.createCipheriv('aes256', aes_key, iv);
    // Use cipher to update it with our data
    var cipher_data_b64 = cipher.update(data, 'ascii', 'base64');
     
    // Finalize the cipher
    cipher_data_b64 += cipher.final('base64');
    console.log("cipher_data_b64 len: " + cipher_data_b64.length);
    console.log("cipher_data_b64: " + cipher_data_b64);
    
    var iv_b64 = new Buffer(iv, 'binary').toString('base64');
    console.log("iv_b64 len: " + iv_b64.length);
    console.log("iv_b64: " + iv_b64);

    var cipher_contents_b64 = iv_b64 + cipher_data_b64;
    
    console.log("cipher_contents_b64 length: " + cipher_contents_b64.length);
    console.log("cipher_contents_b64: " + cipher_contents_b64);
    
    // Create a digest on the cipher using HMAC-256
    var hmac = crypto.createHmac('sha256', hmac_key);
    
    // Update the digest with data
    hmac.update(cipher_contents_b64);
 
    // Encodes final digest
    var digest_b64 = hmac.digest('base64');
    console.log("digest_b64 length: " + digest_b64.length);
    console.log("digest_b64: " + digest_b64);

    // Create the complete signature composed of the cipher & signature
    var signature_b64 = cipher_contents_b64 + digest_b64;

    return signature_b64;
}
//------------------------------------------------------------------------------
// Generate base64 encoded AES-256 + HMAC-256 key = 32 bytes + 32 bytes
var key_b64 = generate_key_string(256);  
console.log("key_b64: " + key_b64);

// Extract AES-256 & HMAC-256 keys from generated_key_string
var keys = extract_keys(key_b64);
var aes_key = keys[0];
var hmac_key = keys[1];

// Encrypt & sign the data using AES-256 & HMAC-256 and then base64 encode it
var data = "hello node.js world!";

var signature_b64 = encrypt(aes_key, hmac_key, data);
console.log("signature_b64 len: " + signature_b64.length);
console.log("signature_b64: " + signature_b64);
//------------------------------------------------------------------------------
// Create an HTTP server
var http = require('http');

// Serve up the base64 signature
var s = http.createServer(function(req, res) {
    res.writeHead(200, {'Content-Type' : 'text/plain'});
    res.end(signature_b64);
});

s.listen(1337, '127.0.0.1');
//==============================================================================
