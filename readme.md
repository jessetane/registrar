# registrar
A digital signature based identity memorization, recognition and administration protocol.

> WARNING: this is alpha software, please don't use it in production!

## Why
Using digital signatures instead of passwords for identitiy verification could provide several advantages:
* uniform credential strength
* improved non-repudiation guarantees
* phishing resistance

## How
[NaCL](http://nacl.cr.yp.to) for cryptos. Bring your own storage. I've put together a SQL backed implementation [here](https://github.com/jessetane/registrar-sql). It would be cool to add IndexedDB and leveldb implementations.

## Example

Register an identity with three keys that requires at least two signatures to authenticate:
```javascript
var Registrar = require('registrar')
var Storage = require('registrar-sql')
var mysql = require('mysql')
var nacl = require('tweetnacl')

var r = new Registrar({
  crypto: nacl,
  storage: new Storage(mysql.createPool({
    user: 'foo',
    password: 'bar',
    database: 'baz'
  }))
})

var key1 = nacl.sign.keypair()
var key2 = nacl.sign.keypair()
var key3 = nacl.sign.keypair()

r.getChallenge(function (err, challenge) {
  if (err) throw err
  r.register(challenge, 2, [
    {
      signature: nacl.sign(challenge, key1.secretKey),
      publicKey: key1.publicKey
    }, {
      signature: nacl.sign(challenge, key2.secretKey),
      publicKey: key2.publicKey
    }, {
      signature: nacl.sign(challenge, key3.secretKey),
      publicKey: key3.publicKey
    }
  ], function (err, identity) {
    console.log(err, identity)
  })
})
```

Authenticate with any two keys:
```javascript
r.getChallenge(function (err, challenge) {
  if (err) throw err
  r.authenticate(challenge, [
    {
      signature: nacl.sign(challenge, key1.secretKey),
      publicKey: key1.publicKey
    }, {
      signature: nacl.sign(challenge, key3.secretKey),
      publicKey: key3.publicKey
    }
  ], function (err, identity) {
    console.log(err, identity)
  })
})
```

Make updates:
```javascript
var updates = []

// change factor count (number of signatures required to authenticate)
updates.push(1)

// add a new key
var aNewKey = nacl.sign.keyPair()
updates.push({
  signature: nacl.sign(challenge, aNewKey.secretKey),
  publicKey: aNewKey.publicKey
})

// remove an old key
updates.push(
  nacl.hash(key1.publicKey)
)

r.getChallenge(function (err, challenge) {
  if (err) throw err
  r.update(challenge, [
    {
      signature: nacl.sign(challenge, key2.secretKey),
      publicKey: key2.publicKey
    }, {
      signature: nacl.sign(challenge, key3.secretKey),
      publicKey: key3.publicKey
    }
  ], updates, function (err) {
    console.log(err)
  })
})
```

## Testing
This module includes an abstract test suite that aims to make implementing and testing storage backends straightforward. Each group of tests requires an isolated environment, so a storage implementation's tests should look something like this:

> Note that in order to verify consistency during testing, storage implementations need to expose a special method `getIdentityCount`.

```javascript
require('registrar/test')(createDatabase)

function createDatabase (cb) {
  var storage = new StorageImplementation()
  storage.getIdentityCount = function (cb) {
    var identityCount = 0
    // count the identities here...
    cb(null, identityCount)
  }
  cb(null, storage)
})
```

## API

### `var r = new Registrar(opts)`
The constructor.
1. `opts`
  * `crypto` An NaCL implementation with [this API](https://github.com/dchest/tweetnacl-js)
  * `storage` A storage backend with [this API](https://github.com/jessetane/registrar-sql)

### `r.getChallenge(cb)`
This method passes a 64 byte nonce to `cb` that must be signed over for authentication.

### `r.register(challenge, factorCount, signatures, cb)`
1. `challenge` Uint8Array
2. `factorCount` Number
3. `signatures` Array
4. `cb` Function

Specify an initial factor count for the new identity and at least as many unique signatures. Signature objects should look like: 
```javascript
{
  signature: <Uint8Array>,
  publicKey: <Uint8Array>
}
```

If the call completes successfully, `cb` will receive a string representation of the storage backend's identifier for the new identity as its second paramter.

### `r.authenticate(challenge, signatures, cb)`
1. `challenge` Uint8Array
2. `signatures` Array
3. `cb` Function

Verifies:
* Each signature in `signatures`
* That each signature was created by a unique key belonging to a single `identity`
* That at least `identity.factorCount` signatures were provided

Authentication is performed internally by all methods other than `getChallenge` and `register`.

### `r.update(challenge, signatures, changes, cb)`
1. `challenge` Uint8Array
2. `signatures` Array
3. `changes` Array
4. `cb` Function

Identitites may add and remove keys as they see fit, although at least `identity.factorCount` keys must remain registered at any given time.

* To add a key, add its signature to `changes`.
* To remove a key, add the hash of its public key to `changes`
* To set the number of signatures required for authenticatication (`identity.factorCount`), add a Number to `changes`.

### `r.deregister(challenge, signatures, cb)`
1. `challenge` Uint8Array
2. `signatures` Array
3. `cb` Function

Allows an identity to deregister itself.

## Prior art / Inspiration
* [OpenSSH](http://www.openssh.com)
* [SSL/TLS](https://tools.ietf.org/html/rfc5246)
* [TACK](http://tack.io)
* [HPKP](https://tools.ietf.org/html/rfc7469)
* [keyboot](https://github.com/substack/keyboot)

## License
Public domain. No Warranty.
