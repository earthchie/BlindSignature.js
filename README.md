# BlindSignature.js
Make anonymous vote possible!

This is the client-side implementation of https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js.

# Installation

1. include `forge.js` dependency on your page.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js"></script>
```

2. include BlindSignature.js on your page.

```html
<script src="./path/to/BlindSignature.js"></script>
```

# Usage

1. The Signer prepares a keypair, then give `publicKeyPem` to the Author.

```javascript
const keypair = forge.pki.rsa.generateKeyPair(2048);
const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
```

2. The Author prepares a blinded ballot. Then send `blindedMessage` to Signer.

```javascript
const Author = new BlindSignature.author(publicKeyPem);
const message = JSON.stringify({
    wallet_address: '0x000000...00000', // Ethereum address, for example
    vote: 1
});
const blindedMessage = Author.blind(message);
console.log(blindedMessage);
```

3. The Signer sign blinded-ballot. Send the `blindSignature` back to the Author.

```javascript
const Signer = new BlindSignature.signer(privateKeyPem);
const blindSignature = Signer.sign(blindedMessage);
console.log(blindSignature);
```

4. The Author unblinds the `blindSignature` to make the `finalSignature`, aka signature. Then assemble the `ballot`. Send the `ballot` to Taller over the anonymous channel. For example Ethereum Network with an anonymous wallet.

```javascript
const finalSignature = Author.unblind(blindSignature);
const ballot = {
    body: message,
    signature: finalSignature
};
console.log(ballot);
```

The Author can also verify the signature using the public key. (the public key has been registered in step #2)

```javascript
const verifyResult = Author.verify();
console.log(verifyResult);
```

or

```javascript
const signatureBigInt = new forge.jsbn.BigInteger(finalSignature.replace('0x', ''), 16);
const verifyResult = BlindSignature.verifyWithPublicKey(signatureBigInt, keypair.publicKey, message);
console.log(verifyResult);
```

5. The Signer verifies the signature compared with the original message they've never seen using the private key. (the private key has been registered in step #3)

```javascript
const verifyResult2 = Signer.verify(ballot.signature, ballot.body);
console.log(verifyResult2);
```

or

```javascript
const signatureBigInt = new forge.jsbn.BigInteger(finalSignature.replace('0x', ''), 16);
const verifyResult2 = BlindSignature.verifyWithPrivateKey(signatureBigInt, keypair.privateKey, message);
console.log(verifyResult2);
```

6. If you are dealing with DomeCloud's e-election [smart contract](https://gist.github.com/earthchie/68c5fdb86c41f1fe691a64f2d7314b9d). You'll need these variables:

```
const N_factor = Signer.N_factor();
const ballotBody = BlindSignature.ascii2hex(message);
const ballotSignature = finalSignature; // from step #4 -> Author.unblind(blindSignature)
```

Also to make the vote anonymous. The voter (the Author) must create a new wallet every time, and submit the ballot to the smart contract using EIP-2771. With EIP-2771, voters do not need to pay transaction gas, so there is no way to track down the origin of the gas and the voter's identity.

# License
MIT
