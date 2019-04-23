var bank = require('./bank_modules')
var jsonStream = require('duplex-json-stream')
var net = require('net')
var sodium = require('sodium-native')
var fs = require('fs')

var secretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
var publicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
var symmKey = sodium.sodium_malloc(sodium.crypto_secretbox_KEYBYTES)

var hashLog

// load existing keypair / establish new one
try {
  secretKey.fill(fs.readFileSync('key.secret', 'ascii'), 'hex')
  publicKey.fill(fs.readFileSync('key.public', 'ascii'), 'hex')
} catch (err) {
  if (err.code === 'ENOENT') {
    sodium.crypto_sign_keypair(publicKey, secretKey)

    fs.writeFile('key.secret', secretKey.toString('hex'), function (err) {
      if (err) throw err
    })
    fs.writeFile('key.public', publicKey.toString('hex'), function (err) {
      if (err) throw err
    })
  }
}
sodium.sodium_mprotect_noaccess(secretKey)

// load symmetric key / establish new one
try {
  symmKey.fill(fs.readFileSync('key.symm', 'ascii'), 'hex')
} catch (err) {
  sodium.randombytes_buf(symmKey)
  fs.writeFile('key.symm', symmKey.toString('hex'), function (err) {
    if (err) throw err
  })
}
sodium.sodium_mprotect_noaccess(symmKey)

// load and decrypt existing log or initiate blank log
try {
  var log = JSON.parse(fs.readFileSync('./encrypt.log'))
  hashLog = JSON.parse(fs.readFileSync('./encrypt_hash.log'))

  var nonce = Buffer.from(log.nonce, 'hex')
  var cipher = Buffer.from(log.cipher, 'hex')
  var message = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)

  var hashNonce = Buffer.from(hashLog.nonce, 'hex')
  var hashCipher = Buffer.from(hashLog.cipher, 'hex')
  var hashMessage = Buffer.alloc(hashCipher.length - sodium.crypto_secretbox_MACBYTES)

  sodium.sodium_mprotect_readonly(symmKey)
  sodium.crypto_secretbox_open_easy(message, cipher, nonce, symmKey)
  sodium.crypto_secretbox_open_easy(hashMessage, hashCipher, hashNonce, symmKey)
  sodium.sodium_mprotect_noaccess(symmKey)

  log = JSON.parse(message.toString('ascii'))
  hashLog = JSON.parse(hashMessage.toString('ascii'))
} catch (err) {
  if (err.code === 'ENOENT') {
    console.log('The bank just opened!')
    log = [{ value: {}, hash: Buffer.alloc(sodium.crypto_generichash_BYTES), signature: Buffer.alloc(sodium.crypto_sign_BYTES) }]
    sodium.crypto_generichash(log[0].hash, Buffer.from(log[0].hash.toString('hex') + JSON.stringify(log[0].value)))

    sodium.sodium_mprotect_readonly(secretKey)
    sodium.crypto_sign_detached(log[0].signature, log[0].hash, secretKey)
    sodium.sodium_mprotect_noaccess(secretKey)

    log[0].hash = log[0].hash.toString('hex')
    log[0].signature = log[0].signature.toString('hex')

    hashLog = [bank.hashToHex(JSON.stringify([]))]
  } else {
    console.log(err)
  }
}

// set up TCP server
var server = net.createServer(function (socket) {
  socket = jsonStream(socket)
  var state = log.reduce(bank.updateState, {})

  socket.on('data', function (msg) {
    // load hashCount and verify hash chain, signatures and hashCount before taking order
    var hashCount = hashLog.slice(-1)[0]
    if (!(bank.hashChain(log) === log[log.length - 1].hash) || (!bank.verifySignatureChain(log, publicKey))) {
      socket.end({ error: 'log verification failed.' })
      return
    } else if (msg.hashCount !== hashCount) {
      socket.end({ error: 'Invalid hash.' })
    }

    if (msg.cmd !== 'register') {
      if (!(state.hasOwnProperty(msg.customerNumber))) {
        socket.end({ error: 'please, register first.' })
      } else if (sodium.crypto_sign_verify_detached(Buffer.from(msg.signature, 'hex'), Buffer.from(msg.customerId, 'hex'), publicKey)) {
        socket.end({ error: 'Invalid signature.' })
      }
    }
    console.log('Bank received:', msg)

    switch (msg.cmd) {
      case 'balance':
        socket.write({ customer: msg.customer, cmd: 'balance', balance: state[msg.customerNumber] })
        break

      case 'deposit':
        bank.updateState(state, { value: msg })

        sodium.sodium_mprotect_readonly(secretKey)
        log.push({
          value: msg,
          hash: bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)),
          signature: bank.signToHex(bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)), secretKey)
        })
        sodium.sodium_mprotect_noaccess(secretKey)

        socket.write('Order registered.')
        break

      case 'withdraw':
        try {
          bank.updateState(state, { value: msg })
        } catch (err) {
          socket.end(err.message)
          break
        }

        sodium.sodium_mprotect_readonly(secretKey)
        log.push({
          value: msg,
          hash: bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)),
          signature: bank.signToHex(bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)), secretKey)
        })
        sodium.sodium_mprotect_noaccess(secretKey)

        socket.write('Order registered')
        break

      case 'register':

        msg.customerNumber = (Object.keys(state).length + 1).toString()
        socket.write({ 'customerNumber': msg.customerNumber })

        sodium.sodium_mprotect_readonly(secretKey)
        log.push({
          value: msg,
          hash: bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)),
          signature: bank.signToHex(bank.hashToHex(log[log.length - 1].hash + JSON.stringify(msg)), secretKey)
        })
        sodium.sodium_mprotect_noaccess(secretKey)

        bank.updateState(state, { value: msg })
        break
    }

    hashLog.push(bank.hashToHex(hashCount))

    var persistentLog = JSON.stringify(log, null, 2)

    // encrypt current logs and save them for next restart
    sodium.sodium_mprotect_readonly(symmKey)
    var encryptLog = bank.encryptToHex(Buffer.from(persistentLog), symmKey)
    var encryptHashLog = bank.encryptToHex(Buffer.from(JSON.stringify(hashLog, 2)), symmKey)
    sodium.sodium_mprotect_noaccess(symmKey)

    fs.writeFileSync('encrypt.log', JSON.stringify(encryptLog))
    fs.writeFileSync('encrypt_hash.log', JSON.stringify(encryptHashLog))
  })
})

server.listen(3876)
