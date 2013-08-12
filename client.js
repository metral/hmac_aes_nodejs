//==============================================================================
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
function extract_keys(key_b64, data) {
    // Decode base64 to get binary key
    var key = new Buffer(key_b64, 'base64').toString('binary');
    
    // Extract AES & HMAC keys (both are 256 bits aka 32 bytes)
    var aes_key = key.substring(0,(key.length - SIG_SIZE));
    var hmac_key = key.substring((key.length - SIG_SIZE));

    return [aes_key, hmac_key];
}
//------------------------------------------------------------------------------
function decrypt(aes_key, hmac_key, data) {
    // Create an initialization vector using the default AES block size
    
    console.log("data len=" + data.length);
    
    var digest_b64 = data.substring((data.length - 44));
    var cipher_contents_b64 = data.substring(0, (data.length - 44));
    console.log("digest_b64: " + digest_b64);
    console.log("digest_b64 len: " + digest_b64.length);
    console.log("cipher_contents_b64: " + cipher_contents_b64);
    console.log("cipher_contents_64 len: " + cipher_contents_b64.length);

    // Create a digest on the cipher using HMAC-256
    var hmac = crypto.createHmac('sha256', hmac_key);
    // Update the digest with data
    hmac.update(cipher_contents_b64);
    // Encodes final digest
    var reconstructed_digest = hmac.digest('base64');
     
    if (reconstructed_digest != digest_b64) {
        console.log("\n*****Error!*******\n");
        return new Error("Message authentication failed!");
    }

    var iv_b64 = cipher_contents_b64.substring(0, (cipher_contents_b64.length - 44));
    var iv = Buffer(iv_b64, 'base64').toString('binary');
    console.log("iv_b64 len: " + iv_b64.length);
    console.log("iv_b64: " + iv_b64);
    
    var cipher_data_b64 = cipher_contents_b64.substring(cipher_contents_b64.length - 44);
    console.log("cipher_data_b64 len: " + cipher_data_b64.length);
    console.log("cipher_data_b64: " + cipher_data_b64);

    // Create AES-256 decipher
    var decipher = crypto.createDecipheriv('aes256', aes_key, iv);
    // Use cipher to update it with our data
    var decipher_data = decipher.update(cipher_data_b64, 'base64', 'ascii');
    
    // Finalize the decipher
    decipher_data += decipher.final('ascii');
    

    console.log("Message: " + decipher_data);
    // Create the complete signature composed of the cipher & signature
    //var signature = cipher + digest;

    //return signature;
}
//------------------------------------------------------------------------------
// Get base64 encoded AES-256 + HMAC-256 key = 32 bytes + 32 bytes
//var key_b64 = "jYsATU6JTCEW4pEUomAgndIucBkQ25yt+es9BOeE3BzwGvHGRD6s9pq9M1mh+q5hnpyaSUtLPTiOhitb4YDkOw=="
var key_b64 = "<INSERT_KEY_HERE>"

// Extract AES-256 & HMAC-256 keys from 
var keys = extract_keys(key_b64);
var aes_key = keys[0];
var hmac_key = keys[1];

// Create an HTTP Request
var http = require('http');

var options = {
    host: '127.0.0.1',
    port: '1337',
    method: 'GET'
};

var c = http.get(options, function(res) {
    var data = "";
    res.setEncoding('ascii');
    console.log('RESPONSE: ' + res.statusCode);
    
    res.on('data', function(chunk) {
        data += chunk.toString();
    });

    res.on('end', function(chunk) {
        //signature_b64 = new Buffer(data, 'base64').toString('binary');
        console.log("signature_b64: " + data);
        
        decrypt(aes_key, hmac_key, data);
    });
})
//==============================================================================
