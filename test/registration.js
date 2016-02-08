module.exports = function (_createStorage) {
  createStorage = _createStorage
}

var Registrar = require('../')
var nacl = require('tweetnacl')
var verifyCredentials = require('./common').verifyCredentials
var tape = require('tape')

var createStorage = null
var registrar = null
var key = nacl.sign.keyPair()

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

tape('fail to register with an invalid factor count', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.register(challenge, 0, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(err.message, 'factor count must be greater than or equal to one')
      t.equal(id, undefined)
    })
  })
})

tape('fail to register with fewer signatures than the specified factor count', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.register(challenge, 1, [], function (err, id) {
      t.equal(err.message, 'factor count is greater than the number of signatures provided')
      t.equal(id, undefined)
    })
  })
})

tape('register with a single key', function (t) {
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
    })
  })
})

tape('fail to register with another identity\'s key', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var newKey = nacl.sign.keyPair()
    registrar.register(challenge, 2, [
      {
        signature: nacl.sign.detached(challenge, newKey.secretKey),
        publicKey: newKey.publicKey
      }, {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(err.message, 'already registered')
      t.equal(id, undefined)
    })
  })
})

tape('register with multiple keys and a factor count greater than one', function (t) {
  t.plan(6)
  var keyring = [
    nacl.sign.keyPair(),
    nacl.sign.keyPair(),
    nacl.sign.keyPair()
  ]
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.register(challenge, 2, keyring.map(function (pair) {
      return {
        signature: nacl.sign.detached(challenge, pair.secretKey),
        publicKey: pair.publicKey
      }
    }), function (err, id) {
      t.error(err)
      t.ok(id)
      verifyCredentials(registrar, keyring, 2, t)
    })
  })
})

tape('only accept one of five simultaneous registrations with identical keys', function (t) {
  t.plan(8)
  registrar.storage.getIdentityCount(function (err, existingIdentityCount) {
    if (err) throw err
    var n = 5
    var key = nacl.sign.keyPair()
    var successfulRegistrations = 0
    var failedRegistrations = 0
    for (var i = 0; i < 5; i++) {
      registrar.getChallenge(function (err, challenge) {
        t.error(err)
        registrar.register(challenge, 1, [
          {
            signature: nacl.sign.detached(challenge, key.secretKey),
            publicKey: key.publicKey
          }
        ], done)
      })
    }
    function done (err) {
      if (err) {
        if (err.message === 'already registered') {
          failedRegistrations++
        } else {
          throw err
        }
      } else {
        successfulRegistrations++
      }
      if (--n === 0) {
        t.equal(successfulRegistrations, 1)
        t.equal(failedRegistrations, 4)
        registrar.storage.getIdentityCount(function (err, identityCount) {
          if (err) throw err
          t.equal(identityCount, existingIdentityCount + 1)
        })
      }
    }
  })
})

tape('close storage', function (t) {
  registrar.storage.close()
  t.end()
})
