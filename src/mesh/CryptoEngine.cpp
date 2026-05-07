#include "CryptoEngine.h"
#include "architecture.h"

#if !(MESHTASTIC_EXCLUDE_PKI)
#include "NodeDB.h"
#include "aes-ccm.h"
#include "meshUtils.h"
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <SHA256.h>
#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
#if !defined(ARCH_STM32WL)
#define CryptRNG RNG
#endif

/**
 * Create a public/private key pair with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The destination for the private key.
 */
void CryptoEngine::generateKeyPair(uint8_t *pubKey, uint8_t *privKey)
{
    CryptRNG.begin(optstr(APP_VERSION));
    if (myNodeInfo.device_id.size == 16) {
        CryptRNG.stir(myNodeInfo.device_id.bytes, myNodeInfo.device_id.size);
    }
    auto noise = random();
    CryptRNG.stir((uint8_t *)&noise, sizeof(noise));

    LOG_DEBUG("Generate Curve25519 keypair");
    Curve25519::dh1(public_key, private_key);
    memcpy(pubKey, public_key, sizeof(public_key));
    memcpy(privKey, private_key, sizeof(private_key));
}

/**
 * Regenerate a public key from an existing private key.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The source for the private key.
 */
bool CryptoEngine::regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey)
{
    if (!memfll(privKey, 0, sizeof(private_key))) {
        Curve25519::eval(pubKey, privKey, 0);
        if (Curve25519::isWeakPoint(pubKey)) {
            LOG_ERROR("PKI key generation failed. Specified private key results in a weak");
            memset(pubKey, 0, 32);
            return false;
        }
        memcpy(private_key, privKey, sizeof(private_key));
        memcpy(public_key, pubKey, sizeof(public_key));
    } else {
        LOG_WARN("X25519 key generation failed due to blank private key");
        return false;
    }
    return true;
}
#endif

/**
 * Derive a PFS-capable encryption key by combining two ECDH operations:
 *   ss1 = ECDH(our_static_priv, remote_static_pub)   -> authentication
 *   ss2 = ECDH(ephemeral_priv, remote_static_pub)     -> forward secrecy
 *   key = SHA256(ss1 || ss2)
 *
 * On the decrypt side the caller swaps which key is "ephemeral":
 *   ss1 = ECDH(our_static_priv, remote_static_pub)    -> same as above
 *   ss2 = ECDH(our_static_priv, remote_ephemeral_pub) -> mirror of above
 *
 * @param remoteStaticPub  The remote node's long-lived public key (32 bytes).
 * @param ephemeralPriv    Ephemeral private key (encrypt side) or our static
 *                         private key again (decrypt side). 32 bytes.
 * @param ephemeralPub     Ephemeral public key to DH against (decrypt side)
 *                         or remote static pub again (encrypt side). 32 bytes.
 *                         On encrypt, pass remoteStaticPub here too; the
 *                         ephemeralPriv already differs so the result differs.
 * @param outKey           Destination for the 32-byte derived key.
 * @return true on success.
 */
bool CryptoEngine::derivePFSKey(const uint8_t *remoteStaticPub,
                                const uint8_t *ephemeralPriv,
                                const uint8_t *ephemeralTarget,
                                uint8_t *outKey)
{
    uint8_t ss_static[32];
    uint8_t ss_ephemeral[32];
    uint8_t local_priv[32];
    uint8_t combined[64];

    // ss1: static-static ECDH (provides authentication)
    memcpy(ss_static, remoteStaticPub, 32);
    memcpy(local_priv, private_key, 32);
    if (!Curve25519::dh2(ss_static, local_priv)) {
        LOG_WARN("PFS: static-static DH failed");
        memset(local_priv, 0, 32);
        return false;
    }

    // ss2: ephemeral ECDH (provides forward secrecy)
    memcpy(ss_ephemeral, ephemeralTarget, 32);
    uint8_t eph_priv_copy[32];
    memcpy(eph_priv_copy, ephemeralPriv, 32);
    if (!Curve25519::dh2(ss_ephemeral, eph_priv_copy)) {
        LOG_WARN("PFS: ephemeral DH failed");
        memset(local_priv, 0, 32);
        memset(eph_priv_copy, 0, 32);
        return false;
    }

    // scrub private material
    memset(local_priv, 0, 32);
    memset(eph_priv_copy, 0, 32);

    // key = SHA256(ss1 || ss2)
    memcpy(combined, ss_static, 32);
    memcpy(combined + 32, ss_ephemeral, 32);

    SHA256 sha;
    sha.reset();
    sha.update(combined, 64);
    sha.finalize(outKey, 32);

    // scrub intermediates
    memset(ss_static, 0, 32);
    memset(ss_ephemeral, 0, 32);
    memset(combined, 0, 64);

    return true;
}

/**
 * Encrypt a packet's payload with per-message PFS.
 *
 * Output layout (bytesOut):
 *   [32 bytes ephemeral public key]
 *   [numBytes ciphertext]
 *   [8 bytes AES-CCM auth tag]
 *   [4 bytes extra nonce]
 *
 * Total overhead: 32 + 8 + 4 = 44 bytes beyond plaintext.
 *
 * @param toNode       MeshPacket `to` field.
 * @param fromNode     MeshPacket `from` field.
 * @param remotePublic Remote node's static Curve25519 public key.
 * @param packetNum    MeshPacket `id` field.
 * @param numBytes     Plaintext length.
 * @param bytes        Plaintext input.
 * @param bytesOut     Output buffer sized at least numBytes + 44.
 */
bool CryptoEngine::encryptCurve25519(uint32_t toNode, uint32_t fromNode,
                                     meshtastic_UserLite_public_key_t remotePublic,
                                     uint64_t packetNum, size_t numBytes,
                                     const uint8_t *bytes, uint8_t *bytesOut)
{
    if (remotePublic.size == 0) {
        LOG_DEBUG("Node %d or their public_key not found", toNode);
        return false;
    }

    // --- generate a one-time ephemeral keypair ---
    uint8_t eph_pub[32];
    uint8_t eph_priv[32];
    Curve25519::dh1(eph_pub, eph_priv);

    // --- derive the combined key ---
    // ss1 = ECDH(our_static, remote_static)  -> auth
    // ss2 = ECDH(eph_priv,   remote_static)  -> PFS
    uint8_t derived_key[32];
    if (!derivePFSKey(remotePublic.bytes, eph_priv, remotePublic.bytes, derived_key)) {
        memset(eph_priv, 0, 32);
        return false;
    }

    // ephemeral private key is never needed again
    memset(eph_priv, 0, 32);

    // --- write ephemeral public key as first 32 bytes of output ---
    memcpy(bytesOut, eph_pub, 32);

    // --- set up pointers past the ephemeral key ---
    uint8_t *ciphertext = bytesOut + 32;
    uint8_t *auth = ciphertext + numBytes;

    // --- random extra nonce ---
    long extraNonceTmp = random();
    LOG_DEBUG("PFS encrypt: random nonce value: %d", extraNonceTmp);

    initNonce(fromNode, packetNum, extraNonceTmp);

    printBytes("PFS encrypt nonce: ", nonce, 13);
    printBytes("PFS encrypt key starts with: ", derived_key, 8);

    // --- AES-CCM encrypt ---
    aes_ccm_ae(derived_key, 32, nonce, 8, bytes, numBytes,
               nullptr, 0, ciphertext, auth);

    // append extra nonce after auth tag
    memcpy(auth + 8, &extraNonceTmp, sizeof(uint32_t));

    // scrub derived key
    memset(derived_key, 0, 32);

    return true;
}

/**
 * Decrypt a PFS-encrypted packet.
 *
 * Expected input layout (bytes):
 *   [32 bytes ephemeral public key]
 *   [payload ciphertext]
 *   [8 bytes AES-CCM auth tag]
 *   [4 bytes extra nonce]
 *
 * @param fromNode     MeshPacket `from` field.
 * @param remotePublic Sender's static Curve25519 public key.
 * @param packetNum    MeshPacket `id` field.
 * @param numBytes     Total length of `bytes` including all overhead.
 * @param bytes        Input buffer.
 * @param bytesOut     Output buffer for decrypted plaintext.
 */
bool CryptoEngine::decryptCurve25519(uint32_t fromNode,
                                     meshtastic_UserLite_public_key_t remotePublic,
                                     uint64_t packetNum,
                                     size_t numBytes, const uint8_t *bytes,
                                     uint8_t *bytesOut)
{
    // minimum size: 32 eph_pub + 0 ciphertext + 8 auth + 4 nonce = 44
    if (numBytes < 44) {
        LOG_WARN("PFS decrypt: packet too small (%d bytes)", numBytes);
        return false;
    }

    if (remotePublic.size == 0) {
        LOG_DEBUG("Node or its public key not found in database");
        return false;
    }

    // --- parse the incoming buffer ---
    const uint8_t *eph_pub = bytes;                        // first 32 bytes
    const uint8_t *ciphertext = bytes + 32;
    size_t ciphertextLen = numBytes - 32 - 12;             // strip eph_pub, auth, extraNonce
    const uint8_t *auth = ciphertext + ciphertextLen;      // 8-byte tag
    uint32_t extraNonce;
    memcpy(&extraNonce, auth + 8, sizeof(uint32_t));
    LOG_INFO("PFS decrypt: random nonce value: %d", extraNonce);

    // --- derive the same combined key ---
    // ss1 = ECDH(our_static, remote_static)   -> same auth component
    // ss2 = ECDH(our_static, remote_ephemeral)-> mirrors sender's eph DH
    uint8_t derived_key[32];
    if (!derivePFSKey(remotePublic.bytes, private_key, eph_pub, derived_key)) {
        return false;
    }

    initNonce(fromNode, packetNum, extraNonce);
    printBytes("PFS decrypt nonce: ", nonce, 13);
    printBytes("PFS decrypt key starts with: ", derived_key, 8);

    // --- AES-CCM decrypt + verify ---
    bool ok = aes_ccm_ad(derived_key, 32, nonce, 8, ciphertext, ciphertextLen,
                         nullptr, 0, auth, bytesOut);

    memset(derived_key, 0, 32);
    return ok;
}

void CryptoEngine::setDHPrivateKey(uint8_t *_private_key)
{
    memcpy(private_key, _private_key, 32);
}

/**
 * Hash arbitrary data using SHA256 (in-place).
 */
void CryptoEngine::hash(uint8_t *bytes, size_t numBytes)
{
    SHA256 h;
    size_t posn;
    uint8_t size = numBytes;
    uint8_t inc = 16;
    h.reset();
    for (posn = 0; posn < size; posn += inc) {
        size_t len = size - posn;
        if (len > inc)
            len = inc;
        h.update(bytes + posn, len);
    }
    h.finalize(bytes, 32);
}

void CryptoEngine::aesSetKey(const uint8_t *key_bytes, size_t key_len)
{
    delete aes;
    aes = nullptr;
    if (key_len != 0) {
        aes = new AESSmall256();
        aes->setKey(key_bytes, key_len);
    }
}

void CryptoEngine::aesEncrypt(uint8_t *in, uint8_t *out)
{
    aes->encryptBlock(out, in);
}

/**
 * Perform raw ECDH with a remote public key (used only for non-PFS paths
 * if needed, e.g. legacy compatibility).
 */
bool CryptoEngine::setDHPublicKey(uint8_t *pubKey)
{
    uint8_t local_priv[32];
    memcpy(shared_key, pubKey, 32);
    memcpy(local_priv, private_key, 32);
    if (!Curve25519::dh2(shared_key, local_priv)) {
        LOG_WARN("Curve25519DH step 2 failed!");
        memset(local_priv, 0, 32);
        return false;
    }
    memset(local_priv, 0, 32);
    return true;
}

#endif
concurrency::Lock *cryptLock;

void CryptoEngine::setKey(const CryptoKey &k)
{
    LOG_DEBUG("Use AES%d key!", k.length * 8);
    key = k;
}

void CryptoEngine::encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    if (key.length > 0) {
        initNonce(fromNode, packetId);
        if (numBytes <= MAX_BLOCKSIZE) {
            encryptAESCtr(key, nonce, numBytes, bytes);
        } else {
            LOG_ERROR("Packet too large for crypto engine: %d. noop encryption!", numBytes);
        }
    }
}

void CryptoEngine::decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    encryptPacket(fromNode, packetId, numBytes, bytes);
}

void CryptoEngine::encryptAESCtr(CryptoKey _key, uint8_t *_nonce, size_t numBytes, uint8_t *bytes)
{
    delete ctr;
    ctr = nullptr;
    if (_key.length == 16)
        ctr = new CTR<AES128>();
    else
        ctr = new CTR<AES256>();
    ctr->setKey(_key.bytes, _key.length);
    static uint8_t scratch[MAX_BLOCKSIZE];
    memcpy(scratch, bytes, numBytes);
    memset(scratch + numBytes, 0, sizeof(scratch) - numBytes);
    ctr->setIV(_nonce, 16);
    ctr->setCounterSize(4);
    ctr->encrypt(bytes, scratch, numBytes);
}

void CryptoEngine::initNonce(uint32_t fromNode, uint64_t packetId, uint32_t extraNonce)
{
    memset(nonce, 0, sizeof(nonce));
    memcpy(nonce, &packetId, sizeof(uint64_t));
    memcpy(nonce + sizeof(uint64_t), &fromNode, sizeof(uint32_t));
    if (extraNonce)
        memcpy(nonce + sizeof(uint32_t), &extraNonce, sizeof(uint32_t));
}

#ifndef HAS_CUSTOM_CRYPTO_ENGINE
CryptoEngine *crypto = new CryptoEngine;
#endif