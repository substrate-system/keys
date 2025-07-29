const enc = new TextEncoder()
const dec = new TextDecoder()

// Step 1: Bob generates ECDH key pair (this could be long-term)
async function generateUserKeyPair () {
    return crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'X25519' },
        true,
        ['deriveKey']
    )
}

// Step 2: Alice derives shared key using her private key and Bob's public key
async function deriveSharedKey (privateKey:CryptoKey, publicKey:CryptoKey) {
    return crypto.subtle.deriveKey(
        {
            name: 'ECDH',
            public: publicKey,
        },
        privateKey,
        {
            name: 'AES-GCM',
            length: 256,
        },
        true,
        ['encrypt', 'decrypt']
    )
}

// Step 3: AES-GCM encrypt/decrypt helpers
async function encryptMessage (key:CryptoKey, plaintext:string) {
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        enc.encode(plaintext)
    )
    return { ciphertext, iv }
}

async function decryptMessage (key: CryptoKey, ciphertext: ArrayBuffer, iv: Uint8Array) {
    const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        ciphertext
    )
    return dec.decode(plaintext)
}

// Demo: Alice sends Bob a message
(async () => {
    // Bob generates ECDH key pair (could be static/long-term)
    const bobKeys = await generateUserKeyPair()

    // Alice generates ephemeral ECDH key pair for this session
    const aliceKeys = await generateUserKeyPair()

    // Each derives the shared AES key
    const aliceSharedKey = await deriveSharedKey(aliceKeys.privateKey, bobKeys.publicKey)
    const bobSharedKey = await deriveSharedKey(bobKeys.privateKey, aliceKeys.publicKey)

    // Alice encrypts message
    const message = 'Hello Bob, this is E2EE!'
    const { ciphertext, iv } = await encryptMessage(aliceSharedKey, message)

    // Bob decrypts it
    const decrypted = await decryptMessage(bobSharedKey, ciphertext, iv)

    console.log('Original:', message)
    console.log('Decrypted:', decrypted)
})()

