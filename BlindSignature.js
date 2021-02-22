/**
 * @name BlindSignature.js
 * @version 1.0.0
 * @update Feb 22, 2021
 * @license MIT License
 * @credits All credit to @kevinejohn. This is the browser version of https://github.com/kevinejohn/blind-signatures/blob/master/rsablind.js
 *
 * @dependencies forge.js <https://github.com/digitalbazaar/forge>
 **/

const BlindSignature = {

    /**
     * @name sign
     * @async no
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
     * |       signed       |     String     | signed message                         |
     * +--------------------+----------------+----------------------------------------+
     **/
    sign: function(blinded, privateKey) {
        const N = new forge.jsbn.BigInteger(privateKey.n.toString());
        const D = new forge.jsbn.BigInteger(privateKey.d.toString());
        return blinded.modPow(D, N);
    },

    /**
     * @name blind
     * @async yes
     * @description blinded message
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
     * |   blinded_message  |   BigInteger   | blinded message                        |
     * +--------------------+----------------+----------------------------------------+
     * |    blind_factor    |   BigInteger   | blind factor for unblind later         |
     * +--------------------+----------------+----------------------------------------+
     **/
    blind: async function(message, publicKey) {

        const messageHash = await this.sha256BigInt(message);
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
            blinded_message: blinded,
            blind_factor: r,
        };
    },

    /**
     * @name unblind
     * @async no
     * @description unblind blind-signed message
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |         signed        |   true   |   BigInteger   | blind-signed message                   |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |      blind_factor     |   true   |  forge Object  | blind factor received from blind()     |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       public_key      |   true   |  forge Object  | forge object of public key             |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |      unblinded        |   BigInteger   | unblinded message                      |
     * +-----------------------+----------------+----------------------------------------+
     **/
    unblind: function(signed, blind_factor, publicKey) {

        const N = new forge.jsbn.BigInteger(publicKey.n.toString());

        return signed.multiply(blind_factor.modInverse(N)).mod(N);
    },

    /**
     * @name verifyWithPublicKey
     * @async yes
     * @description verify unblinded message with public key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       unblinded       |   true   |   BigInteger   | unblinded message to verify            |
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
    verifyWithPublicKey: async function(unblinded, publicKey, message) {

        const messageHash = await this.sha256BigInt(message);
        const E = new forge.jsbn.BigInteger(publicKey.e.toString());
        const N = new forge.jsbn.BigInteger(publicKey.n.toString());

        return messageHash.equals(unblinded.modPow(E, N));
    },

    /**
     * @name verifyWithPrivateKey
     * @async yes
     * @description verify unblinded message with private key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       unblinded       |   true   |   BigInteger   | unblinded message to verify            |
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
    verifyWithPrivateKey: async function(unblinded, privateKey, message) {

        const messageHash = await this.sha256BigInt(message);
        const D = new forge.jsbn.BigInteger(privateKey.d.toString());
        const N = new forge.jsbn.BigInteger(privateKey.n.toString());

        return unblinded.equals(messageHash.modPow(D, N));
    },

    /**
     * @name verifyWithPrivateKey (static)
     * @async yes
     * @description verify unblinded message with private key
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       unblinded       |   true   |   BigInteger   | unblinded message to verify            |
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
    sha256BigInt: async function(message) {

        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => ('00' + b.toString(16)).slice(-2)).join('');

        return new forge.jsbn.BigInteger(hashHex, 16);

    },
}

BlindSignature.author = class {

    /**
     * @name constructor
     * @async no
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
     * @name blind
     * @async yes
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
     * |        blinded        |     String     | base36 blinded message                 |
     * +-----------------------+----------------+----------------------------------------+
     **/
    async blind(message) {
        this.message = message;
        this.blinded = await BlindSignature.blind(this.message, this.publicKey);
        return this.blinded.blinded_message.toString(36);
    }

    /**
     * @name unblind
     * @async no
     * @description unblind the blind-signed message
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |         signed        |   true   |     String     | base36 blind-signed message            |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |       unblinded       |     String     | base36 unblinded message               |
     * +-----------------------+----------------+----------------------------------------+
     **/
    unblind (signed) {
        this.unblinded = BlindSignature.unblind(new forge.jsbn.BigInteger(signed, 36), this.blinded.blind_factor, this.publicKey);
        return this.unblinded.toString(36);
    }

    /**
     * @name verify
     * @async yes
     * @description verify after the message has been unblinded
     * 
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |        result         |     Boolean    | verification result                    |
     * +-----------------------+----------------+----------------------------------------+
     **/
    async verify() {
        return await BlindSignature.verifyWithPublicKey(this.unblinded, this.publicKey, this.message);
    }
    
}

BlindSignature.signer = class {

    /**
     * @name constructor
     * @async no
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
     * @name sign
     * @async no
     * @description sign the blinded message
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |        blinded        |   true   |     String     | base36 blinded message                 |
     * +-----------------------+----------+----------------+----------------------------------------+
     *
     * @output
     * +-----------------------+----------------+----------------------------------------+
     * |         name          |      type      |               description              |
     * +-----------------------+----------------+----------------------------------------+
     * |        signed         |     String     | base36 signed message                  |
     * +-----------------------+----------------+----------------------------------------+
     **/
    sign(blinded) {
        return BlindSignature.sign(new forge.jsbn.BigInteger(blinded, 36), this.privateKey).toString(36);
    }

    /**
     * @name verify
     * @async yes
     * @description verify the blind signature
     * @input
     * +-----------------------+----------+----------------+----------------------------------------+
     * |          name         | required |      type      |               description              |
     * +-----------------------+----------+----------------+----------------------------------------+
     * |       unblinded       |   true   |     String     | base36 unblinded message               |
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
    async verify(unblinded, message) {
        return await BlindSignature.verifyWithPrivateKey(new forge.jsbn.BigInteger(unblinded, 36), this.privateKey, message);
    }
}
