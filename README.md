# learntocrypto-exercise

My solution to the [learntocrypto workshop](https://github.com/sodium-friends/learntocrypto).

`bank.js` script outlines a basic bank capable of supporting multiple customers securely.  
`teller.js` is a CLI tool to communicate with `bank.js` over a TCP server. 

Run `bank.js` with:
```javascript
$ node bank.js
```
and then run `teller.js` using the following commands:

#### Register new user:
```javascript
$ node teller.js register  
// returns customer_number
```

#### Request balance:
```javascript
$ node teller.js balance <customer_number>  
// returns balance for specified customer
```

#### Deposit:
```javascript
$ node teller.js deposit <amount> <customer_number>  
// deposits <amount> into <customer_number> account
// rasies error if customer not registered
```

#### Withdraw:
```javascript
$ node.js teller.js withdraw <amount> <customer_number>  
// withdraws <amount> from <customer_number> account  
// raises error if there are insufficient funds
```