# Example 02

Example for building shares and final payload from raw data and saving keyshares file.
Also read saved keshares file and validate its contents.
There is plenty of different possible scenarios for solo staker, staking provider and web developer.

Some examples:

## Scenario #1
1. Generate keyshares file with operators data in web app
2. Use keyshares file offline to generate encrypted shares using your keystore file and build final payload
3. Use final keyshares file with final payload data to make actual web3 transaction

## Scenario #2
1. Generate keyshares file with operators data in web app
2. Use keyshares file offline to generate encrypted shares using your keystore file
3. Build final payload in web app and send it to web3

## Scenario #3
1. Build keyshares structure with operators data and encrypted shares (or without it)
2. Save keyshares contents in your database
3. When necessary - use keyshares content to build final payload for web3

## Usage

For usage look at `example.ts` file.

### Imports

```javascript
// If you need to read/write key shares into file system
// you might need these imports
import * as path from 'path';
import { promises as fsp } from 'fs';

// In most of the cases it's enough to import only these two classes
import { SSVKeys } from 'ssv-keys';
```

### Initialize SSVKeys SDK

```javascript
const ssvKeys = new SSVKeys();
```

### Encrypting shares

#### Getting private key from keystore using password

```javascript
const keystore = require('./test.keystore.json');
const keystorePassword = 'testtest';

const { publicKey, privateKey } = await ssvKeys.extractKeys(keystore, keystorePassword);
```

#### Encrypting shares

```javascript
const operators = require('./operators.json');      // ['pubkey', ..., 'pubkey']
const operatorIds = require('./operatorIds.json');  // [int, ..., int]

const operators = operatorKeys.map((operatorKey, index) => ({
  id: operatorIds[index],
  operatorKey,
}));

const threshold = await ssvKeys.createThreshold(privateKey, operators);
const shares = await ssvKeys.encryptShares(operators, threshold.shares);
```

### Building final web3 payload

```javascript
let payload = await keyShares.buildPayload({
  publicKey,
  operators,
  shares,
}, {
  ownerAddress: TEST_OWNER_ADDRESS,
  registerNonce: TEST_REGISTER_NONCE,
  privateKey
});
```

Now `payload` contains all required data to be sent to the contract.

### Saving key shares file

It is possible to save all operators' data, encrypted shares and final web3 payload
in one file with strictly defined structure.
It helps to keep the same standard of data across all environments and use the same file
in a different steps of different flows.

Typically key shares file contains few parts:
1. `version` - keeps the version of key shares file
2. `data` - keeps all the operators data and validator public key
3. `payload` - keeps payload details and final compiled payload string

Any of these parts can be empty except version.
When `data` or `payload` is set, it automatically validates all the structures
and data in those structures, such as, validity of public keys, encrypted shares etc.

#### Saving key shares file from json

This is less programmatic way of how to build key shares structure.

```javascript
const keySharesData = {
  version: 'v2',
  data: {
    publicKey: threshold.publicKey,
    operators: operators.map((operator: any, index: string | number) => ({
      id: operatorIds[index],
      publicKey: operator,
    }))
  },
};

// Create SSVKeys instance using key shares data
const ssvKeys = new SSVKeys();
const { publicKey, privateKey } = await ssvKeys.extractKeys(keystore, keystorePassword);
const keyShares = new KeyShares();
const ks = keyShares.fromJson(keySharesData);
await fsp.writeFile('./keyshares.json', ks.toJson(), { encoding: 'utf-8' });
```

#### Saving key shares file from separate data and payload

Let's say, initially you have only operators' data:

```javascript
const keySharesData = {
  version: 'v4',
  data: {
    publicKey: threshold.publicKey,
    operators: [
      {
        id: 1,
        operatorKey: '...',
      },
      // ... 3 more operators ...
    ],
  },
};
```

And at some point you saved it in a key shares file:

```javascript
const ssvKeys = new SSVKeys();
const { publicKey, privateKey } = await ssvKeys.extractKeys(keystore, keystorePassword);
const keyShares = new KeyShares();
const ks = keyShares.fromJson(keySharesData);
await fsp.writeFile('./keyshares.json', ks.toJson(), { encoding: 'utf-8' });
```

Now this file contains only operators' data.
Let's say, now on the next step you want to build shares and save them too.


```javascript
// ...
const threshold = await ssvKeys.createThreshold(privateKey, operators);
const shares = await ssvKeys.encryptShares(operators, threshold.shares);
```

You can save shares as following:

```javascript
keyShares.update({
  ...ks.data,
});
```

And then you can save it again:

```javascript
await fsp.writeFile('./keyshares.json', keyShares.toJson(), { encoding: 'utf-8' });
```

Then if at some point you would need to build payload:

```javascript
// Build final web3 transaction payload and update keyshares file with payload data
const payload = await keyShares.buildPayload({
  publicKey,
  operators,
  encryptedShares,
}, {
  ownerAddress: TEST_OWNER_ADDRESS,
  registerNonce: TEST_REGISTER_NONCE,
  privateKey
});

console.log(payload);
```
