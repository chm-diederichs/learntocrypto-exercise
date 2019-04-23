var bank = require('./bank_modules')
var jsonStream = require('duplex-json-stream')
var net = require('net')
var sodium = require('sodium-native')
var fs = require('fs')

var command = process.argv[2]
var order
var customer
var hashCount

var client = jsonStream(net.connect(3876))

var fileNamePublic = './customers/public/user_key.public'
var fileNameSecret = './customers/secret/user_key.secret'

try {
  hashCount = fs.readFileSync('./hash.counter', 'ascii').toString('hex')
} catch (err) {
  if (err.code === 'ENOENT') {
    hashCount = bank.hashToHex(JSON.stringify([]))
  } else {
    if (err) throw err
  }
}

// client.end({cmd: 'deposit', amount: 100})
if (command === 'register') {
  var newPublicKey = Buffer.alloc(sodium.crypto_sign_PUBLICKEYBYTES)
  var newSecretKey = sodium.sodium_malloc(sodium.crypto_sign_SECRETKEYBYTES)
  sodium.crypto_sign_keypair(newPublicKey, newSecretKey)
  client.end({ cmd: command, 'publicKey': newPublicKey.toString('hex'), 'hashCount': hashCount })
  sodium.sodium_mprotect_noaccess(newSecretKey)
} else {
  if (command === 'balance') {
    customer = process.argv[3]
  } else {
    customer = process.argv[4]
  }
  try {
    // ----->>>>>> improve process.argv[-1] style --------->>>>>>>> make another conditional block for withdraw/deposit

    var filePublic = fileNamePublic.replace('user', customer)
    var fileSecret = fileNameSecret.replace('user', customer)

    console.log(fileSecret, filePublic)

    var secretKey = fs.readFileSync(fileSecret, 'ascii')
    var publicKey = fs.readFileSync(filePublic, 'ascii')

    if (command === 'balance') {
      order = { cmd: command, customerNumber: customer, customerId: publicKey, 'hashCount': hashCount }
    } else {
      order = { cmd: command, customerNumber: customer, customerId: publicKey, amount: parseInt(process.argv[3], 10), 'hashCount': hashCount }
    }

    order.signature = bank.signToHex(JSON.stringify(order), Buffer.from(secretKey, 'hex'))
    console.log(order)
  // hashCount = bank.hashToHex(hashCount)
    client.end(order)
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error('User not registered.')
    }
  }
}
console.log(hashCount)

client.on('data', function (msg) {
  if (msg.hasOwnProperty('customerNumber')) {
    sodium.sodium_mprotect_readwrite(newSecretKey)
    fileNameSecret = fileNameSecret.replace('user', msg.customerNumber)
    fileNamePublic = fileNamePublic.replace('user', msg.customerNumber)

    fs.writeFile(fileNameSecret, newSecretKey.toString('hex'), function (err) {
      if (err) throw err
    })
    fs.writeFile(fileNamePublic, newPublicKey.toString('hex'), function (err) {
      if (err) throw err
    })
    sodium.sodium_memzero(newSecretKey)
    sodium.sodium_munlock(newSecretKey)
  }
  // -------------->>>> need to have bank give new hash, bank stores list of hashes and checks, bank must encrypt hashLog to prevent tampering.
  console.log('Teller received:', msg)
  if (!msg.hasOwnProperty('error')) {
    fs.writeFileSync('./hash.counter', bank.hashToHex(hashCount))
  }
})
