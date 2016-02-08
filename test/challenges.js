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

tape('provide a 64 byte challenge', function (t) {
  t.plan(3)
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    t.equal(challenge.length, 64)
  })
})

tape('close storage', function (t) {
  registrar.storage.close()
  t.end()
})
