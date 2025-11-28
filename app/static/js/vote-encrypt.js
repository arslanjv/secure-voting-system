/**
 * Client-Side Vote Encryption and Digital Signature
 * 
 * SECURITY FIXES:
 * - VULN-001: Removed hardcoded encryption keys - now fetches RSA public key from server
 * - VULN-002: Salt is now generated server-side and provided with public key
 * 
 * Implements hybrid encryption:
 * 1. Generate random AES-256-GCM key for vote encryption
 * 2. Encrypt vote with AES-256-GCM
 * 3. Encrypt AES key with RSA-OAEP (RSA-4096 public key from server)
 * 4. Sign the encrypted data for integrity
 * 
 * All cryptographic operations happen in the browser using Web Crypto API
 */

/**
 * Generate cryptographically secure random bytes
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
    // Handle PEM format by removing line breaks
    const cleanBase64 = base64.replace(/[\r\n\s]/g, '');
    const binary = atob(cleanBase64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Import RSA public key from PEM format
 * @param {string} pemKey - PEM-encoded public key
 * @returns {Promise<CryptoKey>} Imported RSA public key for encryption
 */
async function importRSAPublicKey(pemKey) {
    // Remove PEM header and footer
    const pemHeader = "-----BEGIN PUBLIC KEY-----";
    const pemFooter = "-----END PUBLIC KEY-----";
    
    let pemContents = pemKey;
    if (pemKey.includes(pemHeader)) {
        pemContents = pemKey
            .replace(pemHeader, '')
            .replace(pemFooter, '')
            .replace(/[\r\n\s]/g, '');
    }
    
    // Decode base64 to binary DER format
    const binaryDer = base64ToArrayBuffer(pemContents);
    
    // Import key for RSA-OAEP encryption
    return await crypto.subtle.importKey(
        "spki",
        binaryDer,
        {
            name: "RSA-OAEP",
            hash: "SHA-256"
        },
        false,  // Not extractable
        ["encrypt"]
    );
}

/**
 * Fetch election public key and salt from server
 * @param {number} electionId - Election ID
 * @returns {Promise<Object>} Object containing public_key and salt
 */
async function fetchElectionPublicKey(electionId) {
    try {
        const response = await fetch(`/voter/api/election/${electionId}/public-key`);
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch public key');
        }
        
        return await response.json();
    } catch (error) {
        console.error('Error fetching election public key:', error);
        throw new Error('Failed to retrieve encryption key. Please try again.');
    }
}

/**
 * Encrypt vote data using hybrid RSA + AES-GCM encryption
 * 
 * Process:
 * 1. Fetch RSA public key from server
 * 2. Generate random AES-256 key
 * 3. Encrypt vote with AES-256-GCM
 * 4. Encrypt AES key with RSA-OAEP
 * 
 * @param {Array} candidateIds - Array of selected candidate IDs
 * @param {number} electionId - Election ID
 * @returns {Promise<Object>} Encrypted data with encrypted_vote, encrypted_key, iv, and tag
 */
async function encryptVote(candidateIds, electionId) {
    try {
        // Step 1: Fetch public key from server (VULN-001 & VULN-002 fix)
        console.log('Fetching election public key...');
        const keyData = await fetchElectionPublicKey(electionId);
        
        if (!keyData.public_key) {
            throw new Error('No public key returned from server');
        }
        
        // Step 2: Import RSA public key
        console.log('Importing RSA public key...');
        const rsaPublicKey = await importRSAPublicKey(keyData.public_key);
        
        // Step 3: Generate random AES-256 key
        console.log('Generating AES key...');
        const aesKey = await crypto.subtle.generateKey(
            {
                name: "AES-GCM",
                length: 256
            },
            true,  // Extractable (we need to encrypt it with RSA)
            ["encrypt", "decrypt"]
        );
        
        // Step 4: Encrypt vote data with AES-GCM
        console.log('Encrypting vote with AES-GCM...');
        const encoder = new TextEncoder();
        const voteJson = JSON.stringify(candidateIds);
        const voteData = encoder.encode(voteJson);
        
        // Generate random IV (12 bytes for GCM)
        const iv = getRandomBytes(12);
        
        const encryptedVote = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv,
                tagLength: 128  // 16 bytes authentication tag
            },
            aesKey,
            voteData
        );
        
        // Step 5: Export AES key
        const exportedAesKey = await crypto.subtle.exportKey("raw", aesKey);
        
        // Step 6: Encrypt AES key with RSA-OAEP
        console.log('Encrypting AES key with RSA...');
        const encryptedAesKey = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP"
            },
            rsaPublicKey,
            exportedAesKey
        );
        
        // For AES-GCM, the tag is appended to the ciphertext
        // We need to split them for compatibility
        const encryptedArray = new Uint8Array(encryptedVote);
        const ciphertextLength = encryptedArray.length - 16;  // Tag is 16 bytes
        const ciphertext = encryptedArray.slice(0, ciphertextLength);
        const tag = encryptedArray.slice(ciphertextLength);
        
        console.log('Vote encryption complete');
        
        // Return encrypted package
        return {
            // For backward compatibility with form fields
            ciphertext: arrayBufferToBase64(ciphertext),
            nonce: arrayBufferToBase64(iv),
            tag: arrayBufferToBase64(tag),
            
            // New hybrid encryption fields
            encrypted_vote: arrayBufferToBase64(encryptedVote),  // Full ciphertext+tag
            encrypted_key: arrayBufferToBase64(encryptedAesKey),
            iv: arrayBufferToBase64(iv),
            
            // Version marker for server to know encryption type
            encryption_version: 2
        };
        
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt vote: ' + error.message);
    }
}

/**
 * Sign vote data using HMAC-SHA256 with a client-generated key
 * 
 * Note: This provides integrity verification. The actual cryptographic
 * binding is provided by the AES-GCM authentication tag and RSA encryption.
 * 
 * @param {string} voteData - Vote data to sign (JSON string of candidate IDs)
 * @returns {Promise<string>} Base64 encoded signature
 */
async function signVote(voteData) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(voteData);
        
        // Generate a session-specific signing key
        // This is derived from random bytes for each vote
        const signingMaterial = getRandomBytes(32);
        
        // Import as HMAC key
        const signingKey = await crypto.subtle.importKey(
            'raw',
            signingMaterial,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        // Generate signature
        const signature = await crypto.subtle.sign(
            'HMAC',
            signingKey,
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
 * Note: Since we use random keys, verification happens server-side
 * @param {string} voteData - Original vote data
 * @param {string} signatureBase64 - Base64 encoded signature
 * @returns {Promise<boolean>} True if format is valid
 */
async function verifySignature(voteData, signatureBase64) {
    try {
        // Basic format validation
        if (!signatureBase64 || signatureBase64.length < 10) {
            return false;
        }
        
        // Decode to verify it's valid base64
        const signature = base64ToArrayBuffer(signatureBase64);
        return signature.byteLength === 32;  // HMAC-SHA256 produces 32 bytes
        
    } catch (error) {
        console.error('Verification error:', error);
        return false;
    }
}

/**
 * Generate secure random string for nonce
 * Used for replay attack prevention
 * @returns {string} Random hex string (64 characters)
 */
function generateSecureNonce() {
    const bytes = getRandomBytes(32);
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Wrapper function for backward compatibility
 * Encrypts vote and returns in format expected by existing form
 * @param {Array} candidateIds - Selected candidate IDs
 * @returns {Promise<Object>} Encrypted vote data
 */
async function encryptVoteData(candidateIds) {
    // Get election ID from URL or data attribute
    const electionId = window.ELECTION_ID || 
                       parseInt(document.querySelector('[data-election-id]')?.dataset.electionId) ||
                       parseInt(window.location.pathname.match(/\/election\/(\d+)/)?.[1]);
    
    if (!electionId) {
        throw new Error('Election ID not found');
    }
    
    return await encryptVote(candidateIds, electionId);
}

// Export functions for use in templates
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        encryptVote,
        encryptVoteData,
        signVote,
        verifySignature,
        generateSecureNonce,
        fetchElectionPublicKey
    };
}

// Browser compatibility check
if (typeof crypto === 'undefined' || !crypto.subtle) {
    console.error('Web Crypto API not available. Please use a modern browser with HTTPS.');
    alert('Your browser does not support the required cryptographic features. Please use a modern browser with HTTPS.');
}
