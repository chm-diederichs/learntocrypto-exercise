# learntocrypto-exercise

bank.js script outlines a basic bank capable of supporting multiple customers securely.
teller.js is a CLI tool to communicate with bank.js 

run bank.js and then run teller.js using the following commands:
  register:
    'node teller.js register'
    # returns customer_number
  
  balance:
    'node teller.js balance <customer_number>'
    # returns balance for specified customer
  
  deposit:
    'node teller.js deposit <amount> <customer_number>'
    # deposits <amount> into <customer_number> account
  
  withdraw:
    'node.js teller.js withdraw <amount> <customer_number>'
    # withdraws <amount> from <customer_number> account
    # raises error if there are insufficient funds
