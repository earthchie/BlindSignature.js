# BlindSignature.js
Make anonymous vote possible!
ทำให้การโหวตลับเกิดขึ้นได้จริง!

A major part of this project is the client-side implementation of [kevinejohn's rsablind.js](https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js).

ส่วนสำคัญของโปรเจคนี้ เป็นการแปลงโค้ดจาก [kevinejohn's rsablind.js](https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js) เพื่อให้ทำงานได้บน client-side

![image](https://github.com/earthchie/BlindSignature.js/assets/7013039/2240036e-d02c-4e6e-8a99-0ccd30d9d51f)

![image](https://github.com/earthchie/BlindSignature.js/assets/7013039/d9b47941-9eb9-44f9-9186-8dbef643a7dd)


# Installation วิธีการติดตั้ง

1. include the `forge.js` dependency on your page.
   
เพิ่ม `forge.js` ไปยังหน้าเว็บ

```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/forge/0.10.0/forge.min.js"></script>
```

2. include the `BlindSignature.js` on your page.
   
เพิ่ม `BlindSignature.js` ไปยังหน้าเว็บ

```html
<script src="./path/to/BlindSignature.js"></script>
```

# Usage วิธีใช้งาน

1. The Signer prepares a key pair, then gives the `publicKeyPem` to the Author.

Signer เตรียม key pair จากนั้นส่ง `publicKeyPem` ให้กับ Author

```javascript
const keypair = forge.pki.rsa.generateKeyPair(2048);
const publicKeyPem = forge.pki.publicKeyToPem(keypair.publicKey);
const privateKeyPem = forge.pki.privateKeyToPem(keypair.privateKey);
```

2. The Author prepares a blinded ballot and sends the `blindedMessage` to the Signer.

Author ทำการสร้างบัตรเลือกตั้ง และปกปิดเนื้อหาในบัตรเลือกตั้ง จากนั้นส่ง `blindedMessage` ที่ได้ ให้กับ Signer

```javascript
const Author = new BlindSignature.author(publicKeyPem);
const message = JSON.stringify({
    wallet_address: '0x000000...00000', // Ethereum address, for example
    vote: 1
});
const blindedMessage = Author.blind(message);
console.log(blindedMessage);
```

3. The Signer signs the blinded ballot and sends the `blindSignature` back to the Author.

Signer เซ็นรับรองบัตรเลือกตั้งที่ปกปิดอยู่ แล้วส่ง `blindSignature` กลับไปให้ Author

```javascript
const Signer = new BlindSignature.signer(privateKeyPem);
const blindSignature = Signer.sign(blindedMessage);
console.log(blindSignature);
```

4. The Author unblinds the `blindSignature` to obtain the `finalSignature` and assembles the `ballot`. The Author sends the ballot to Taller over the anonymous channel, for example, the Ethereum Network smart contract with an anonymous wallet.

Author เปิดเผย `blindSignature` ได้รับ `finalSignature` จากนั้นนำไปประกอบรวมกันเป็น `ballot` ซึ่งคือบัตรเลือกตั้งที่สมบูรณ์ จากนั้น Author ส่ง `ballot` ไปยังระบบนับคะแนนเลือกตั้งผ่านช่องทางนิรนาม เช่น ส่งไปยัง Smart Contract บน Ethereum Network ด้วยกระเป๋านิรนาม

```javascript
const finalSignature = Author.unblind(blindSignature);
const ballot = {
    body: message,
    signature: finalSignature
};
console.log(ballot);
```

The Author can also verify the signature using the public key (the public key has been registered in step #2).

Author ตรวจสอบความถูกต้องของลายเซ็นได้ ด้วย public key (public key ได้มาแล้วจากขั้นตอนที่ 2)

```javascript
const verifyResult = Author.verify();
console.log(verifyResult);
```

or หรือ

```javascript
const signatureBigInt = new forge.jsbn.BigInteger(finalSignature.replace('0x', ''), 16);
const verifyResult = BlindSignature.verifyWithPublicKey(signatureBigInt, keypair.publicKey, message);
console.log(verifyResult);
```

5. The Signer verifies the signature by comparing it with the original message they have never seen, using the private key (the private key has been registered in step #3).

Signer ก็ตรวจสอบความถูกต้องของลายเซ็นได้เช่นกัน ด้วย private key แม้ว่าจะไม่เคยเห็นเนื้อหาฉบับจริงเลยก็ตาม (private key ได้มาแล้วจากขั้นตอนที่ 3)


```javascript
const verifyResult2 = Signer.verify(ballot.signature, ballot.body);
console.log(verifyResult2);
```

or หรือ

```javascript
const signatureBigInt = new forge.jsbn.BigInteger(finalSignature.replace('0x', ''), 16);
const verifyResult2 = BlindSignature.verifyWithPrivateKey(signatureBigInt, keypair.privateKey, message);
console.log(verifyResult2);
```

6. If you are dealing with DomeCloud's e-election [smart contract](https://gist.github.com/earthchie/90efd4227b7b5e21c97ed03238f4d46b). you'll need the following variables:

ถ้านำไปใช้งานร่วมกับ DomeCloud's e-election [smart contract](https://gist.github.com/earthchie/90efd4227b7b5e21c97ed03238f4d46b) ต้องใช้ตัวแปรเหล่านี้ด้วย

```
const N_factor = Signer.N_factor();
const ballotBody = BlindSignature.ascii2hex(message);
const ballotSignature = finalSignature; // from step #4 -> Author.unblind(blindSignature)
```

To make the vote anonymous, the voter (the Author) must create a new wallet every time and submit the ballot to the smart contract using EIP-2771. With EIP-2771, voters do not need to pay transaction gas, so there is no way to track down the origin of the gas and the voter's identity.

เพื่อให้การโหวตเป็นโหวตลับ ผู้โหวต (Author) ต้องสร้างกระเป๋าใหม่ทุกครั้งและส่งข้อมูลไปยัง smart contract ด้วยมาตรฐาน EIP-2771 ซึ่งเป็นเทคนิคการส่งธุรกรรมโดยไม่ต้องจ่ายค่า gas การไม่ต้องจ่าย gas ทำให้ไม่ต้องจัดเตรียม gas ซึ่งอาจเป็นช่องทางที่ใช้ติดตามตัวได้ ทำให้สูญเสียความนิรนาม

# License
MIT
