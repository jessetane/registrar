module.exports = function (createStorage) {
  require('./registration')(createStorage)
  require('./authentication')(createStorage)
  require('./updates')(createStorage)
  require('./deregistration')(createStorage)
}
