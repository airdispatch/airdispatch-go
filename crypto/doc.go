// This package implements helper methods to be used
// by the AirDispatch system to take care of all encryption
// needs. It is split into files based on the types of crypto
// included.
//
// --- Crypto
// | - Constants  = Constants used for Encoding and Decoding
// | - Crypto     = Methods needed for all Crypto Files
// | - Encoding   = Encoding Keys to Binary (and back again)
// | - Encryption = AES Encryption and Decryption
// | - Hash       = SHA256 Hashing
// | - Signatures = ECDSA Signing
//
package crypto
