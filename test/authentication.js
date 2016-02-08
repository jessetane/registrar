module.exports = function (_createStorage) {
  createStorage = _createStorage
}

var Registrar = require('../')
var nacl = require('tweetnacl')
var tape = require('tape')

var createStorage = null
var registrar = null
var identity = null
var key = nacl.sign.keyPair()
var otherKey = nacl.sign.keyPair()

tape('create storage', function (t) {
  t.plan(2)
  createStorage(function (err, storage) {
    t.error(err)
    t.ok(storage)
    registrar = new Registrar({
      crypto: nacl,
      storage: storage
    })
  })
})

tape('register an identity', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.register(challenge, 1, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.ok(id !== undefined)
      identity = id
    })
  })
})

tape('fail to authenticate with invalid challenge', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    challenge[0] = challenge[0] + 1
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'invalid challenge')
    })
  })
})

tape('fail to authenticate with no signatures', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    challenge[0] = challenge[0] + 1
    registrar.authenticate(challenge, [], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'at least one signature is required')
    })
  })
})

tape('fail to authenticate with bogus secret key', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var secretKey = new Uint8Array(key.secretKey)
    secretKey[0] = secretKey[0] + 1
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'signature verification failed')
    })
  })
})

tape('fail to authenticate with bogus public key', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var publicKey = new Uint8Array(key.publicKey)
    publicKey[0] = publicKey[0] + 1
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: publicKey
      }
    ], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'signature verification failed')
    })
  })
})

tape('fail to authentication with bogus signature', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var signature = nacl.sign.detached(challenge, key.secretKey)
    signature[0] = signature[0] + 1
    registrar.authenticate(challenge, [
      {
        signature: signature,
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'signature verification failed')
    })
  })
})

tape('fail to authenticate with signature by unrecognized key', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = nacl.sign.keyPair()
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(id, undefined)
      t.equal(err.message, 'unrecognized signature')
    })
  })
})

tape('authenticate', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.equal(id, identity)
    })
  })
})

tape('increase factor count by one and add another key', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [
      2, {
        signature: nacl.sign.detached(challenge, otherKey.secretKey),
        publicKey: otherKey.publicKey
      }
    ], function (err) {
      t.error(err)
    })
  })
})

tape('fail to authenticate with fewer than factor count signatures', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(err.message, '2 signatures required')
    })
  })
})

tape('fail to authenticate using the same key twice', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }, {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(err.message, 'signatures must be unique')
    })
  })
})

tape('fail to authenticate with keys belonging to more than one identity', function (t) {
  t.plan(5)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var newKey = nacl.sign.keyPair()
    registrar.register(challenge, 1, [
      {
        signature: nacl.sign.detached(challenge, newKey.secretKey),
        publicKey: newKey.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.ok(id !== undefined)
      registrar.getChallenge(function (err, challenge) {
        t.error(err)
        registrar.authenticate(challenge, [
          {
            signature: nacl.sign.detached(challenge, key.secretKey),
            publicKey: key.publicKey
          }, {
            signature: nacl.sign.detached(challenge, newKey.secretKey),
            publicKey: newKey.publicKey
          }
        ], function (err, id) {
          t.equal(err.message, 'unrecognized signature')
        })
      })
    })
  })
})

tape('authenticate', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.authenticate(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }, {
        signature: nacl.sign.detached(challenge, otherKey.secretKey),
        publicKey: otherKey.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.equal(id, identity)
    })
  })
})

tape('close storage', function (t) {
  registrar.storage.close()
  t.end()
})
