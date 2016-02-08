module.exports = Registrar

var hexString = require('hex-string')

function Registrar (opts) {
  this.crypto = opts.crypto
  this.storage = opts.storage
  var self = this
  ;[
    'getChallenge',
    'register',
    'authenticate',
    'update',
    'enumerateCredentials',
    'deregister'
  ].forEach(function (method) {
    self[method] = self[method].bind(self)
  })
}

Registrar.prototype.getChallenge = function (cb) {
  this.storage.getChallenge(cb)
}

Registrar.prototype.register = function (challenge, factorCount, signatures, cb) {
  var signaturesProvided = Array.isArray(signatures) ? signatures.length : 0
  if (typeof factorCount !== 'number' || factorCount === 0) {
    return cb(new Error('factor count must be greater than or equal to one'))
  } else if (signaturesProvided < factorCount) {
    return cb(new Error('factor count is greater than the number of signatures provided'))
  }
  var self = this
  this._verifySignatures(challenge, signatures, function (err, publicKeyHashes) {
    if (err) return cb(err)
    self.storage.register(challenge, publicKeyHashes, factorCount, cb)
  })
}

Registrar.prototype.authenticate = function (challenge, signatures, cb) {
  var self = this
  this._verifySignatures(challenge, signatures, function (err, publicKeyHashes) {
    if (err) return cb(err)
    self.storage.authenticate(challenge, publicKeyHashes, cb)
  })
}

Registrar.prototype.update = function (challenge, signatures, changes, cb) {
  if (!Array.isArray(changes) || changes.length === 0) {
    return cb(new Error('no updates requested'))
  }
  var dedupe = {}
  var didUpdateFactorCount = false
  var changesCopy = []
  var i = -1
  while (++i < changes.length) {
    var change = changes[i]
    if (change.publicKey) {
      var publicKeyHash = this.crypto.hash(change.publicKey)
      publicKeyHash.hexRepresentation = hexString.encode(publicKeyHash)
      if (publicKeyHash.hexRepresentation in dedupe) {
        return cb(new Error('cannot update the same key more than once per update'))
      } else {
        if (!this.crypto.sign.detached.verify(challenge, change.signature, change.publicKey)) {
          return cb(new Error('signature verification failed'))
        }
        dedupe[publicKeyHash.hexRepresentation] = true
      }
      change = {
        signature: change.signature,
        publicKey: change.publicKey,
        publicKeyHash: publicKeyHash
      }
    } else if (change.buffer) {
      change = new Uint8Array(change)
      change.hexRepresentation = hexString.encode(change)
      if (change.hexRepresentation in dedupe) {
        return cb(new Error('cannot update the same key more than once per update'))
      } else {
        dedupe[change.hexRepresentation] = true
      }
    } else if (typeof change === 'number') {
      if (didUpdateFactorCount) {
        return cb(new Error('cannot update factor count more than once per update'))
      } else if (change === 0) {
        return cb(new Error('factor count must be greater than or equal to one'))
      }
      didUpdateFactorCount = true
    } else {
      return cb(new Error('unknown update type'))
    }
    changesCopy.push(change)
  }
  var self = this
  this._verifySignatures(challenge, signatures, function (err, publicKeyHashes) {
    if (err) return cb(err)
    self.storage.update(challenge, publicKeyHashes, changesCopy, cb)
  })
}

Registrar.prototype.enumerateCredentials = function (challenge, signatures, cb) {
  var self = this
  this._verifySignatures(challenge, signatures, function (err, publicKeyHashes) {
    if (err) return cb(err)
    self.storage.enumerateCredentials(challenge, publicKeyHashes, cb)
  })
}

Registrar.prototype.deregister = function (challenge, signatures, cb) {
  var self = this
  this._verifySignatures(challenge, signatures, function (err, publicKeyHashes) {
    if (err) return cb(err)
    self.storage.deregister(challenge, publicKeyHashes, cb)
  })
}

Registrar.prototype._verifySignatures = function (challenge, signatures, cb) {
  if (!Array.isArray(signatures) || signatures.length === 0) {
    return cb(new Error('at least one signature is required'))
  }
  var dedupe = {}
  var publicKeyHashes = []
  var i = -1
  while (++i < signatures.length) {
    var signature = signatures[i]
    var publicKey = signature.publicKey
    var publicKeyHash = this.crypto.hash(publicKey)
    publicKeyHash.hexRepresentation = hexString.encode(publicKeyHash)
    if (publicKeyHash.hexRepresentation in dedupe) {
      return cb(new Error('signatures must be unique'))
    }
    if (!this.crypto.sign.detached.verify(challenge, signature.signature, publicKey)) {
      return cb(new Error('signature verification failed'))
    }
    dedupe[publicKeyHash.hexRepresentation] = true
    publicKeyHashes.push(publicKeyHash)
  }
  cb(null, publicKeyHashes)
}
