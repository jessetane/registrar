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

tape('register two identities', function (t) {
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

tape('fail to deregister if authentication fails', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var key = nacl.sign.keyPair()
    registrar.deregister(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.equal(err.message, 'unrecognized signature')
      t.equal(id, undefined)
    })
  })
})

tape('deregister', function (t) {
  t.plan(4)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    registrar.deregister(challenge, [
      {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    ], function (err, id) {
      t.error(err)
      t.equal(id, identity)
      registrar.storage.getIdentityCount(function (err, identityCount) {
        if (err) throw err
        t.equal(identityCount, 0)
      })
    })
  })
})

tape('close storage', function (t) {
  registrar.storage.close()
  t.end()
})
