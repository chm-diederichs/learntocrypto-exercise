// convert hash to hex string
var sodium = require('sodium-native')
var toExport = {

  hashToHex: function (data) {
    var input = Buffer.from(data)
    var output = Buffer.alloc(sodium.crypto_generichash_BYTES)

    sodium.crypto_generichash(output, input)
    return output.toString('hex')
  },

  updateState: function (state, event) {
    if (event.value.cmd === 'register') { // this won't work since initState has no event.cmd
      state[event.value.customerNumber] = 0
      return state
    }
    var customerBalance = state[event.value.customerNumber]
    switch (event.value.cmd) {
      case 'deposit':
        if (customerBalance == null) throw new Error('Invalid customer')

        customerBalance += event.value.amount
        state[event.value.customerNumber] = customerBalance
        return state

      case 'withdraw':
        if (customerBalance == null) throw new Error('Invalid customer')

        if (event.value.amount > customerBalance) throw new Error('Insufficient funds.')

        customerBalance -= event.value.amount
        state[event.value.customerNumber] = customerBalance
        return state

      case undefined:
        return state

      default:
        throw new Error('Invalid command')
    }
  },

  // verify transaction hash-chain
  hashChain: function (log, prevHash = Buffer.alloc(sodium.crypto_generichash_BYTES).toString('hex')) {
    var i
    for (i = 0; i < log.length; i++) {
      prevHash = toExport.hashToHex(Buffer.from(prevHash + JSON.stringify(log[i].value))) ///  u dont wanna add them
    }
    return (prevHash)
  },

  // verify transaction signatures
  verifySignatureChain: function (log, publicKey) {
    var i
    for (i = 0; i < log.length; i++) {
      if (!sodium.crypto_sign_verify_detached(Buffer.from(log[i].signature, 'hex'), Buffer.from(log[i].hash, 'hex'), publicKey)) {
        return false
      }
    }
    return true
  },

  // symmetric encryption
  encryptToHex: function (data, key) {
    var cipher = Buffer.alloc(data.length + sodium.crypto_secretbox_MACBYTES)
    var nonce = Buffer.alloc(sodium.crypto_secretbox_NONCEBYTES)

    sodium.randombytes_buf(nonce)
    sodium.crypto_secretbox_easy(cipher, data, nonce, key)

    return ({
      cipher: cipher.toString('hex'),
      nonce: nonce.toString('hex')
    })
  },

  // sign transaction
  signToHex: function (hash, secretKey) {
    var signatureBuffer = Buffer.alloc(sodium.crypto_sign_BYTES)
    sodium.crypto_sign_detached(signatureBuffer, Buffer.from(hash, 'hex'), secretKey)
    return signatureBuffer.toString('hex')
  }
}

module.exports = toExport
