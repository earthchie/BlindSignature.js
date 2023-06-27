/**
 * @name BlindSignature.js
 * @version 2.0.2
 * @update JUN 27, 2023
 * @license MIT License
 * @author THANARAT KUAWATTANAPHAN <earthchie@gmail.com>
 * @credits @kevinejohn. This is the browser version of https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js
 *
 * @dependencies forge.js <https://github.com/digitalbazaar/forge>
 **/

const BlindSignature = {

    /**
     * @name sign (static)
     * @description sign blinded message
     * @input
     * +--------------------+----------+----------------+----------------------------------------+
     * |        name        | required |      type      |               description              |
     * +--------------------+----------+----------------+----------------------------------------+
     * |      blinded       |   true   |   BigInteger   | Blind message                          |
     * +--------------------+----------+----------------+----------------------------------------+
     * |     privateKey     |   true   |  forge Object  | forge object of private key            |
     * +--------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +--------------------+----------------+----------------------------------------+
     * |        name        |      type      |               description              |
     * +--------------------+----------------+----------------------------------------+
     * |  blindSignature   |     String     | blind signature                        |
     * +--------------------+----------------+----------------------------------------+
     **/
    sign: function (blinded, privateKey) {
        const N = new forge.jsbn.BigInteger(privateKey.n.toString());
        const D = new forge.jsbn.BigInteger(privateKey.d.toString());
        return blinded.modPow(D, N);
    },

    /**
     * @name blind (static)
     * @description blind the message
     * @input
     * +--------------------+----------+----------------+----------------------------------------+
     * |        name        | required |      type      |               description              |
     * +--------------------+----------+----------------+----------------------------------------+
     * |      message       |   true   |     String     | message to blind                       |
     * +--------------------+----------+----------------+----------------------------------------+
     * |     publicKey      |   true   |  forge Object  | forge object of public key             |
     * +--------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +--------------------+----------------+----------------------------------------+
     * |       name         |      type      |               description              |
     * +--------------------+----------------+----------------------------------------+
     * |   blindedMessage  |   BigInteger   | blinded message to sign                |
     * +--------------------+----------------+----------------------------------------+
     * |    blindFactor    |   BigInteger   | blind factor for unblind later         |
     * +--------------------+----------------+----------------------------------------+
     **/
    blind: function (message, publicKey) {

        const messageHash = this.sha256BigInt(message);
        const N = new forge.jsbn.BigInteger(publicKey.n.toString());
        const E = new forge.jsbn.BigInteger(publicKey.e.toString());
        const One = new forge.jsbn.BigInteger('1');

        let gcd;
        let r;
        do {
            r = new forge.jsbn.BigInteger(crypto.getRandomValues(new Uint8Array(64))).mod(N);
            gcd = r.gcd(N);
        } while (!gcd.equals(One) || r.compareTo(N) >= 0 || r.compareTo(One) <= 0);

        const blinded = messageHash.multiply(r.modPow(E, N)).mod(N);

        return {
            blindedMessage: blinded,
            blindFactor: r,
        };
    },

    /**
     * @name unblind (static)
     * @description unblind blind signature (reveal final signature)
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |    blindSignature    |   true   |   BigInteger   | blind signature                        |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |      blindFactor     |   true   |  forge Object  | blind factor received from blind()     |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       publicKey      |   true   |  forge Object  | forge object of public key             |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |   finalSignature     |   BigInteger   | final signature                        |
     * +-----------------------+----------------+----------------------------------------+
     **/
    unblind: function (blindSignature, blindFactor, publicKey) {

        const N = new forge.jsbn.BigInteger(publicKey.n.toString());

        return blindSignature.multiply(blindFactor.modInverse(N)).mod(N);
    },

    /**
     * @name verifyWithPublicKey (static)
     * @description verify the final signature with public key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |    finalSignature    |   true   |   BigInteger   | final signature to verify              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       publicKey       |   true   |  forge Object  | forge object of public key             |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        message        |   true   |     String     | original message                       |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |         result        |    Boolean     | verification result                    |
     * +-----------------------+----------------+----------------------------------------+
     **/
    verifyWithPublicKey: function (finalSignature, publicKey, message) {

        const messageHash = this.sha256BigInt(message);
        const E = new forge.jsbn.BigInteger(publicKey.e.toString());
        const N = new forge.jsbn.BigInteger(publicKey.n.toString());

        return messageHash.equals(finalSignature.modPow(E, N));
    },

    /**
     * @name verifyWithPrivateKey (static)
     * @description verify the final signature with private key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |    finalSignature    |   true   |   BigInteger   | final signature to verify              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       privateKey      |   true   |  forge Object  | forge object of private key            |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        message        |   true   |     String     | original message                       |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |         result        |    Boolean     | verification result                    |
     * +-----------------------+----------------+----------------------------------------+
     **/
    verifyWithPrivateKey: function (finalSignature, privateKey, message) {

        const messageHash = this.sha256BigInt(message);
        const D = new forge.jsbn.BigInteger(privateKey.d.toString());
        const N = new forge.jsbn.BigInteger(privateKey.n.toString());

        return finalSignature.equals(messageHash.modPow(D, N));
    },

    /**
     * @name sha256BigInt (static)
     * @description sha256 but the result is in BigInt format
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        message        |   true   |     String     | original message to hash               |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |         result        |    BigInt      | base16 sha-256 result                  |
     * +-----------------------+----------------+----------------------------------------+
     **/
    sha256BigInt: function (message) {

        let md = forge.md.sha256.create();
        md.update(message);

        return new forge.jsbn.BigInteger(md.digest().toHex(), 16);

    },

    /**
     * @name ascii2hex (static)
     * @description convert string to hex. Useful for converting message before submiting to the smart contract.
     * @input
     * +-----------------------+----------+----------------+-------------------------------------------+
     * |          name         | required |      type      |                 description               |
     * +-----------------------+----------+----------------+-------------------------------------------+
     * |          str          |   true   |     String     | String to be converted to base16 string   |
     * +-----------------------+----------+----------------+-------------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |         result        |    String      | base16 string                          |
     * +-----------------------+----------------+----------------------------------------+
     **/
    ascii2hex: function (str) {
        let arr1 = [];
        for (let n = 0, l = str.length; n < l; n++) {
            let hex = Number(str.charCodeAt(n)).toString(16);
            arr1.push(hex);
        }
        return '0x' + arr1.join('');
    }
}

BlindSignature.author = class {

    /**
     * @name constructor
     * @description construct object for author
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       publicKey       |   true   |  String (PEM)  | signer's public key                    |
     * +-----------------------+----------+----------------+----------------------------------------+
     **/
    constructor(publicKeyPEM) {
        this.publicKey = forge.pki.publicKeyFromPem(publicKeyPEM);
    }

    /**
     * @name N_factor
     * @description get the N_factor of signer which required to blind the message
     * @input
     * none
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |       N_factor        |     String     | base16 of n factor                     |
     * +-----------------------+----------------+----------------------------------------+
     **/
    N_factor() {
        return '0x' + this.publicKey.n.toString(16);
    }

    /**
     * @name blindFactor
     * @description get the latest blind factor
     * @input
     * none
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |     blindFactor      |     String     | base16 of blind factor                 |
     * +-----------------------+----------------+----------------------------------------+
     **/
    blindFactor() {
        return this.blinded ? '0x'+this.blinded.blindFactor.toString(16) : false;
    }

    /**
     * @name blind
     * @description blind the message
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        message        |   true   |     String     | original message                       |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |        blinded        |     String     | base16 blinded message                 |
     * +-----------------------+----------------+----------------------------------------+
     **/
    blind(message) {
        this.message = message;
        this.blinded = BlindSignature.blind(this.message, this.publicKey);
        return '0x' + this.blinded.blindedMessage.toString(16);
    }

    /**
     * @name unblind
     * @description unblind the blind signature
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |    blindSignature    |   true   |     String     | base16 blind signature                 |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |      blindFactor     |  false   |     String     | blind factor of the message            |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |    final signature    |     String     | base16 string of final signature       |
     * +-----------------------+----------------+----------------------------------------+
     **/
    unblind(blindSignature, blindFactor) {
        if(blindFactor){
            blindFactor = new forge.jsbn.BigInteger(blindFactor.replace('0x', ''), 16);
        }else{
            blindFactor = this.blinded.blindFactor
        }
        this.finalSignature = BlindSignature.unblind(new forge.jsbn.BigInteger(blindSignature.replace('0x', ''), 16), blindFactor, this.publicKey);
        return '0x' + this.finalSignature.toString(16);
    }

    /**
     * @name verify
     * @description verify the final signature with public key
     * 
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |        result         |     Boolean    | verification result                    |
     * +-----------------------+----------------+----------------------------------------+
     **/
    verify() {
        return BlindSignature.verifyWithPublicKey(this.finalSignature, this.publicKey, this.message);
    }

}

BlindSignature.signer = class {

    /**
     * @name constructor
     * @description construct object for signer
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       privateKey      |   true   |  String (PEM)  | signer's private key                   |
     * +-----------------------+----------+----------------+----------------------------------------+
     **/
    constructor(privateKey) {
        this.privateKey = forge.pki.privateKeyFromPem(privateKey);
    }

    /**
     * @name N_factor
     * @description get the N_factor of signer which required to blind the message
     * @input
     * none
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |       N_factor        |     String     | base16 of n factor                     |
     * +-----------------------+----------------+----------------------------------------+
     **/
    N_factor() {
        return '0x' + this.privateKey.n.toString(16);
    }

    /**
     * @name sign
     * @description sign the blinded message
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        blinded        |   true   |     String     | base16 blinded message                 |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |    blind signature    |     String     | base16 signed message                  |
     * +-----------------------+----------------+----------------------------------------+
     **/
    sign(blinded) {
        return '0x' + BlindSignature.sign(new forge.jsbn.BigInteger(blinded.replace('0x', ''), 16), this.privateKey).toString(16);
    }

    /**
     * @name verify
     * @description verify the blind signature with private key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |    blindSignature    |   true   |     String     | base16 blind signature                 |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        message        |   true   |     String     | original message                       |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |        result         |     Boolean    | verification result                    |
     * +-----------------------+----------------+----------------------------------------+
     **/
    verify(blindSignature, message) {
        return BlindSignature.verifyWithPrivateKey(new forge.jsbn.BigInteger(blindSignature.replace('0x', ''), 16), this.privateKey, message);
    }
}
