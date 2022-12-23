# BlindSignature.js
Make anonymous vote possible!

This is the client side implementation of https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js.

# Installation

1. include `forge.js` dependency to your page.

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js"></script>
```

2. include BlindSignature.js to your page.

```html
<script src="./path/to/BlindSignature.js"></script>
```

# Usage

1. Signer prepare keypair, then give `publicKeyPem` to Author.

```javascript
const keypair = forge.pki.rsa.generateKeyPair(2048);
const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
```

2. Author prepare blinded ballot. Send `blinded` to Signer.

```javascript
const Author = new BlindSignature.author(publicKeyPem);
const vote = JSON.stringify({
    wallet_address: '0x000000...00000', // ethereum address, for example
    vote: 1
});
const blinded = Author.blind(vote);
console.log(blinded);
```

3. Signer sign blinded-ballot. Send `signed` back to Author.

```javascript
const Signer = new BlindSignature.signer(privateKeyPem);
const signed = Signer.sign(blinded);
console.log(signed);
```

4. Author unblind ballot. Then create an actual ballot. Send `ballot` to Taller over the anonymous channel. For example: Ethereum Network with anonymous wallet.

```javascript
const signature = Author.unblind(signed);
const ballot = {
    body: vote,
    signature: signature
};
console.log(ballot);
```

Author can also verify signature if needed.

```javascript
const verify_result = Author.verify();
console.log(verify_result);
```

5. Signer verify signature compare with original message that they've never seen.

```javascript
const verify_result2 = Signer.verify(ballot.signature, ballot.body);
console.log(verify_result2);
```

6. If you are dealing with DomeCloud's e-election (smart contract)[https://gist.github.com/earthchie/68c5fdb86c41f1fe691a64f2d7314b9d]. You'll need these variables:

```
const N_factor = Signer.N_factor();
const ballotBody = BlindSignature.ascii2hex(vote);
const ballotSignature = signature; // from step #4 -> Author.unblind(signed)
```

# License
MIT
