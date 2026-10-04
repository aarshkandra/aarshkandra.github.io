using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using System.Security.Cryptography;

namespace AarshRemote.Agent.Protocol;

/// <summary>Ed25519 over BouncyCastle (managed, no native dependency). Keys are raw: 32-byte seed / 32-byte public key.</summary>
internal static class Ed25519
{
    public static byte[] NewSeed() => RandomNumberGenerator.GetBytes(32);

    public static byte[] PublicKeyFromSeed(byte[] seed) => new Ed25519PrivateKeyParameters(seed, 0).GeneratePublicKey().GetEncoded();

    public static byte[] Sign(byte[] seed, byte[] data)
    {
        var signer = new Ed25519Signer();
        signer.Init(true, new Ed25519PrivateKeyParameters(seed, 0));
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    public static bool Verify(byte[] publicKey, byte[] data, byte[] signature)
    {
        if (publicKey.Length != 32 || signature.Length != 64) return false;
        try
        {
            var verifier = new Ed25519Signer();
            verifier.Init(false, new Ed25519PublicKeyParameters(publicKey, 0));
            verifier.BlockUpdate(data, 0, data.Length);
            return verifier.VerifySignature(signature);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Short stable identifier for logs (never the key itself).</summary>
    public static string Fingerprint(byte[] publicKey) => Convert.ToHexString(SHA256.HashData(publicKey))[..16].ToLowerInvariant();
}
