var nacl = require('tweetnacl')
var hexString = require('hex-string')

exports.verifyCredentials = function (registrar, expected, factorCount, t) {
  registrar.getChallenge(function (err, challenge) {
    t.error(err)
    var signatures = expected.slice(0, factorCount).map(function (key) {
      return {
        signature: nacl.sign.detached(challenge, key.secretKey),
        publicKey: key.publicKey
      }
    })
    registrar.enumerateCredentials(challenge, signatures, function (err, publicKeyHashes) {
      t.error(err)
      t.deepEqual(
        publicKeyHashes.map(function (hash) {
          return hexString.encode(hash)
        }).sort(),
        expected.map(function (key) {
          return hexString.encode(nacl.hash(key.publicKey))
        }).sort()
      )
    })
  })
}
