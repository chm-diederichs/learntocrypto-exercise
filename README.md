# learntocrypto-exercise

`bank.js` script outlines a basic bank capable of supporting multiple customers securely.
`teller.js` is a CLI tool to communicate with `bank.js` 

run `bank.js` and then run `teller.js` using the following commands:

  **register new user**:
```javascript
node teller.js register  
// returns customer_number
```

   Teller.js generates and saves a new keypair for new customer and passes public key to bank.js, each subsequent request is then signed by the customer and the bank verifies the request before processing.
  
  **request balance**:
```javascript
node teller.js balance <customer_number>  
// returns balance for specified customer
```

  **deposit**:
```javascript
node teller.js deposit <amount> <customer_number>  
// deposits <amount> into <customer_number> account
// rasies error if customer not registered
```

  **withdraw**:
```javascript
node.js teller.js withdraw <amount> <customer_number>  
// withdraws <amount> from <customer_number> account  
// raises error if there are insufficient funds
```