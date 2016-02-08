module.exports = function (_createStorage) {
  createStorage = _createStorage
}

var Registrar = require('../')
var nacl = require('tweetnacl')
var verifyCredentials = require('./common').verifyCredentials
var tape = require('tape')

var createStorage = null
var registrar = null
var keyring = [
  nacl.sign.keyPair(),
  nacl.sign.keyPair(),
  nacl.sign.keyPair(),
  nacl.sign.keyPair()
]

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
    var key = keyring[0]
    registrar.register(challenge, 1, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.ok(id !== undefined)
    })
  })
})

tape('fail to commit updates if none are requested', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [], function (err) {
      t.equal(err.message, 'no updates requested')
    })
  })
})

tape('fail to commit unknown types of updates', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [ 'a' ], function (err) {
      t.equal(err.message, 'unknown update type')
    })
  })
})

tape('fail to commit updates that attempt to add the same key more than once', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var otherKey = keyring[1]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [
      {
        signature: nacl.sign.detached(challenge, otherKey.secretKey),
        publicKey: otherKey.publicKey
      }, {
        signature: nacl.sign.detached(challenge, otherKey.secretKey),
        publicKey: otherKey.publicKey
      }
    ], function (err) {
      t.equal(err.message, 'cannot update the same key more than once per update')
    })
  })
})

tape('fail to commit updates that attempt to remove the same key more than once', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var otherKey = keyring[1]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [
      nacl.hash(key.publicKey),
      nacl.hash(key.publicKey)
    ], function (err) {
      t.equal(err.message, 'cannot update the same key more than once per update')
    })
  })
})

tape('fail to commit updates that attempt to add and delete the same key simultaneously', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var otherKey = keyring[1]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [
      {
        signature: nacl.sign.detached(challenge, otherKey.secretKey),
        publicKey: otherKey.publicKey
      },
      nacl.hash(otherKey.publicKey)
    ], function (err) {
      t.equal(err.message, 'cannot update the same key more than once per update')
    })
  })
})

tape('fail to commit updates that attempt to update factor count more than once', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var otherKey = keyring[1]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [ 2, 3 ], function (err) {
      t.equal(err.message, 'cannot update factor count more than once per update')
    })
  })
})

tape('fail to commit updates that attempt to set factor count to zero', function (t) {
  t.plan(2)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var otherKey = keyring[1]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [ 0 ], function (err) {
      t.equal(err.message, 'factor count must be greater than or equal to one')
    })
  })
})

tape('fail to commit updates if any key addition fails signature verification', function (t) {
  t.plan(5)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = keyring[0]
    var newKey1 = keyring[1]
    var newKey2 = keyring[2]
    var badSig = nacl.sign.detached(challenge, newKey2.secretKey)
    badSig[0] = badSig[0] + 1
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], [
      2, {
        signature: nacl.sign.detached(challenge, newKey1.secretKey),
        publicKey: newKey1.publicKey
      }, {
        signature: badSig,
        publicKey: newKey2.publicKey
      }
    ], function (err) {
      t.equal(err.message, 'signature verification failed')
      verifyCredentials(registrar, keyring.slice(0, 1), 1, t)
    })
  })
})

tape('add some keys', function (t) {
  t.plan(5)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, keyring[0].secretKey),
        publicKey: keyring[0].publicKey
      }
    ], [
      {
        signature: nacl.sign.detached(challenge, keyring[1].secretKey),
        publicKey: keyring[1].publicKey
      }, {
        signature: nacl.sign.detached(challenge, keyring[2].secretKey),
        publicKey: keyring[2].publicKey
      }
    ], function (err) {
      t.error(err)
      verifyCredentials(registrar, keyring.slice(0, 3), 1, t)
    })
  })
})

tape('simultaneously increase factor count and add and remove keys', function (t) {
  t.plan(5)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var keyToAdd = keyring[3]
    var keyToRemove = keyring.shift()
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, keyToRemove.secretKey),
        publicKey: keyToRemove.publicKey
      }
    ], [
      2,
      {
        signature: nacl.sign.detached(challenge, keyToAdd.secretKey),
        publicKey: keyToAdd.publicKey
      },
      nacl.hash(keyToRemove.publicKey)
    ], function (err) {
      t.error(err)
      verifyCredentials(registrar, keyring, 2, t)
    })
  })
})

tape('fail to commit updates if factor count would exceed the number of registered keys', function (t) {
  t.plan(5)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key1 = keyring[1]
    var key2 = keyring[2]
    registrar.update(challenge, [
      {
        signature: nacl.sign.detached(challenge, key1.secretKey),
        publicKey: key1.publicKey
      }, {
        signature: nacl.sign.detached(challenge, key2.secretKey),
        publicKey: key2.publicKey
      }
    ], [
      nacl.hash(key1.publicKey),
      nacl.hash(key2.publicKey)
    ], function (err) {
      t.equal(err.message, 'factor count would exceed the number of registered keys')
      verifyCredentials(registrar, keyring, 2, t)
    })
  })
})

tape('close storage', function (t) {
  registrar.storage.close()
  t.end()
})
