/**
 * Client-Side Vote Encryption and Digital Signature
 * Implements AES-256-GCM encryption and digital signatures using Web Crypto API
 * 
 * Security: All cryptographic operations happen in the browser before sending to server
 */

/**
 * Generate random bytes for encryption key/nonce
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
function getRandomBytes(length) {
    return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64 encoded string
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64 - Base64 string
 * @returns {ArrayBuffer} Array buffer
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Derive encryption key from passphrase using PBKDF2
 * In production, use server-provided public key for hybrid encryption
 * @returns {Promise<CryptoKey>} Encryption key
 */
async function deriveKey() {
    // For demonstration, we use a static key derivation
    // In production, implement proper key exchange (e.g., RSA + AES hybrid)
    const password = 'SECURE_VOTING_SYSTEM_KEY_2024'; // This should be election-specific
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        enc.encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits', 'deriveKey']
    );

    // Use election-specific salt (in production, get from server)
    const salt = enc.encode('election_salt_' + window.location.pathname);

    return crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
}

/**
 * Encrypt vote data using AES-256-GCM
 * @param {Array} candidateIds - Array of selected candidate IDs
 * @returns {Promise<Object>} Encrypted data with nonce and tag
 */
async function encryptVote(candidateIds) {
    try {
        // Convert vote data to JSON string then to bytes
        const voteData = JSON.stringify(candidateIds);
        const encoder = new TextEncoder();
        const data = encoder.encode(voteData);

        // Generate encryption key
        const key = await deriveKey();

        // Generate random nonce (12 bytes for GCM)
        const nonce = getRandomBytes(12);

        // Encrypt using AES-GCM
        const encrypted = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: nonce,
                tagLength: 128 // 16 bytes authentication tag
            },
            key,
            data
        );

        // Split ciphertext and tag (last 16 bytes)
        const encryptedArray = new Uint8Array(encrypted);
        const ciphertextLength = encryptedArray.length - 16;
        const ciphertext = encryptedArray.slice(0, ciphertextLength);
        const tag = encryptedArray.slice(ciphertextLength);

        return {
            ciphertext: arrayBufferToBase64(ciphertext),
            nonce: arrayBufferToBase64(nonce),
            tag: arrayBufferToBase64(tag)
        };

    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt vote data');
    }
}

/**
 * Generate digital signature for vote using HMAC-SHA256
 * In production, use proper digital signatures (ECDSA or RSA-PSS)
 * @param {string} voteData - Vote data to sign
 * @returns {Promise<string>} Base64 encoded signature
 */
async function signVote(voteData) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(voteData);

        // Import signing key (in production, use proper key management)
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode('DIGITAL_SIGNATURE_KEY_2024'),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );

        // Generate signature
        const signature = await crypto.subtle.sign(
            'HMAC',
            keyMaterial,
            data
        );

        return arrayBufferToBase64(signature);

    } catch (error) {
        console.error('Signing error:', error);
        throw new Error('Failed to sign vote data');
    }
}

/**
 * Verify digital signature (for verification page)
 * @param {string} voteData - Original vote data
 * @param {string} signatureBase64 - Base64 encoded signature
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifySignature(voteData, signatureBase64) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(voteData);
        const signature = base64ToArrayBuffer(signatureBase64);

        // Import verification key
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            encoder.encode('DIGITAL_SIGNATURE_KEY_2024'),
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['verify']
        );

        // Verify signature
        return await crypto.subtle.verify(
            'HMAC',
            keyMaterial,
            signature,
            data
        );

    } catch (error) {
        console.error('Verification error:', error);
        return false;
    }
}

/**
 * Generate secure random string for nonce
 * @returns {string} Random hex string
 */
function generateSecureNonce() {
    const bytes = getRandomBytes(32);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

// Export functions for use in templates
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        encryptVote,
        signVote,
        verifySignature,
        generateSecureNonce
    };
}

// Browser compatibility check
if (typeof crypto === 'undefined' || !crypto.subtle) {
    console.error('Web Crypto API not available. Please use a modern browser with HTTPS.');
    alert('Your browser does not support the required cryptographic features. Please use a modern browser with HTTPS.');
}
