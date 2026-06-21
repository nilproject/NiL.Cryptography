using System;
using System.Security.Cryptography;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Encryption.Modes.Gcm;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls12;
using NiL.Tools;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)]
public class EcdheEcdsaAes128GcmSha256 : CipherSuiteBase
{
    private const int _implicitNonceLen = 4;
    private const int _explicitNonceLen = 8;
    private const int _authTagLen = 16;

    private readonly EcdhKeyDerivation _derivationAlgorithm;
    private readonly WeierstrassEcdsa _signatureAlgorithm;

    public EcdheEcdsaAes128GcmSha256(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa)
    {
        _derivationAlgorithm = keyDerivationAlgorithm;
        _signatureAlgorithm = ecdsa;

        var keysSizes = new KeysSizes(0, 16, _implicitNonceLen);
        PseudoRandomFunction = new PseudoRandomFunction(Hmac, keysSizes);
    }

    public override IHashFunction HashFunction => Sha256.Instance;
    public override IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm => _derivationAlgorithm;
    public override ISignatureAlgorithm SignatureAlgorithm => _signatureAlgorithm;
    public override PseudoRandomFunction PseudoRandomFunction { get; protected set; }

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls12];

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion)
    {
        return new EncryptDecryptProcessor(
            tlsVersion,
            keysSet,
            Hmac);
    }

    private sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private readonly KeysSet12 _keysSet;
        private readonly GcmMode _outputCipher;
        private readonly GcmMode _inputCipher;
        private readonly TlsVersion _tlsVersion;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(TlsVersion tlsVersion, KeysSet12 keysSet, Hmac hmac)
        {
            if (keysSet.OurWriteKey is null || keysSet.TheirWriteKey is null
                    || keysSet.OurWriteIV is null || keysSet.TheirWriteIV is null)
                throw new ArgumentNullException();

            _keysSet = keysSet;
            _outputCipher = new GcmMode(new Encryption.Aes(keysSet.OurWriteKey));
            _inputCipher = new GcmMode(new Encryption.Aes(keysSet.TheirWriteKey));
            _hmac = hmac;
            _tlsVersion = tlsVersion;
        }

        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType)
        {
            var nonceLen = _implicitNonceLen + _explicitNonceLen;
            var authBuffer = new BigEndianWriteBuffer(8 + 1 + 2 + 2, true);

            var nonce = stackalloc byte[nonceLen];

            for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                nonce[i] = _keysSet.TheirWriteIV[i];

            for (var i = _keysSet.TheirWriteIV.Length; i < nonceLen; i++)
                nonce[i] = inputBuffer[i - _keysSet.TheirWriteIV.Length];

            var cipheredDataLen = inputBuffer.Length - _explicitNonceLen - _authTagLen;

            authBuffer.Uint64(_inputSeqNumber++);
            authBuffer.Uint8((byte)tlsContentType);
            authBuffer.Uint16((ushort)_tlsVersion);
            authBuffer.Uint16((ushort)cipheredDataLen);

            var output = new byte[cipheredDataLen];
            var authTag = new byte[16];

            fixed (byte* inputPtr = &inputBuffer[_explicitNonceLen])
            {
                _inputCipher.Decrypt(
                    authBuffer,
                    new Span<byte>(nonce, nonceLen),
                    new Span<byte>(inputPtr, cipheredDataLen),
                    new Span<byte>(output),
                    authTag);

                for (var i = 0; i < authTag.Length; i++)
                {
                    if (authTag[i] != inputBuffer[inputBuffer.Length - _authTagLen + i])
                        throw new InvalidOperationException("Incorrect Auth Tag");
                }
            }

            return output;
        }

        public unsafe ArraySegment<byte> Encrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType)
        {
            var outputBuffer = new BigEndianWriteBuffer(_explicitNonceLen + inputBuffer.Length + _authTagLen, true);
            var nonceLen = _implicitNonceLen + _explicitNonceLen;
            var nonce = stackalloc byte[nonceLen];
            Span<byte> authData = default;

            for (var i = 0; i < _keysSet.OurWriteIV.Length; i++)
                nonce[i] = _keysSet.OurWriteIV[i];

            var explicitNonce =
                ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 48)
                ^ ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 24)
                ^ ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 0);

            var enp = (byte*)&explicitNonce;
            for (var i = _keysSet.OurWriteIV.Length; i < nonceLen; i++)
                nonce[i] = enp[i - _keysSet.OurWriteIV.Length];

            outputBuffer.Bytes(new Span<byte>(nonce + _implicitNonceLen, _explicitNonceLen));

            const int authDataLen = 8 + 1 + 2 + 2;
            authData = new ArraySegment<byte>(outputBuffer.Buffer, _explicitNonceLen + inputBuffer.Length, authDataLen);

            // temporary reuse (AuthTagLen > authDataLen)
            outputBuffer.Length = _explicitNonceLen + inputBuffer.Length;
            outputBuffer.Position = outputBuffer.Length;
            outputBuffer.Uint64(_outputSeqNumber++);
            outputBuffer.Uint8((byte)tlsContentType);
            outputBuffer.Uint16((ushort)_tlsVersion);
            outputBuffer.Uint16((ushort)inputBuffer.Length);

            _outputCipher.Encrypt(
                authData,
                new Span<byte>(nonce, _implicitNonceLen + _explicitNonceLen),
                inputBuffer,
                new ArraySegment<byte>(outputBuffer.Buffer, _explicitNonceLen, inputBuffer.Length),
                new ArraySegment<byte>(outputBuffer.Buffer, _explicitNonceLen + inputBuffer.Length, 16));

            return outputBuffer.Buffer;
        }
    }
}
