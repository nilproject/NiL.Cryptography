using System;
using NiL.Cryptography.Encryption;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls13;
using NiL.Tools;

namespace NiL.Cryptography.Tls.CipherSuites;

public abstract class Tls13CipherSuiteBase : CipherSuiteBase
{
    private readonly IPreMasterKeyDerivationAlgorithm _derivationAlgorithm;
    private readonly ISignatureAlgorithm _signatureAlgorithm;

    protected Tls13CipherSuiteBase(IPreMasterKeyDerivationAlgorithm derivationAlgorithm, ISignatureAlgorithm signatureAlgorithm)
    {
        PseudoRandomFunction = null;
        _derivationAlgorithm = derivationAlgorithm;
        _signatureAlgorithm = signatureAlgorithm;
    }

    public override IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm => _derivationAlgorithm;

    public override ISignatureAlgorithm SignatureAlgorithm => _signatureAlgorithm;

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls13];

    protected class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private const int _nonceLen = 12;
        private const int _authTagLen = 16;

        private readonly IAeadCipher _outputCipher;
        private readonly IAeadCipher _inputCipher;
        private readonly TlsVersion _tlsVersion;
        private readonly TrafficKeyingMaterial _ourKeyMaterial;
        private readonly TrafficKeyingMaterial _theirKeyMaterial;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(
            TlsVersion tlsVersion,
            TrafficKeyingMaterial ourKeyMaterial,
            TrafficKeyingMaterial theirKeyMaterial,
            Hmac hmac,
            IAeadCipher outputCipher = null,
            IAeadCipher inputCipher = null)
        {
            if (ourKeyMaterial.WriteKey is null || theirKeyMaterial.WriteKey is null
                    || ourKeyMaterial.WriteIv is null || theirKeyMaterial.WriteIv is null)
                throw new ArgumentNullException();

            _hmac = hmac;
            _tlsVersion = tlsVersion;
            _ourKeyMaterial = ourKeyMaterial;
            _theirKeyMaterial = theirKeyMaterial;
            _outputCipher = outputCipher;
            _inputCipher = inputCipher;
        }

        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> input, TlsContentType tlsContentType)
        {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
            // TLSInnerPlaintext
            var realDataLen = input.Length - _authTagLen;
            var outputBuffer = new BigEndianWriteBuffer(Math.Max(5, realDataLen), true)
            {
                Length = realDataLen
            };

            // additional_data
            Span<byte> aad = stackalloc byte[5]
            {
                (byte)TlsContentType.ApplicationData,
                0x03, 0x03, // TlsVersion.Tls12
                (byte)(input.Length >> 8), (byte)(input.Length)
            };

            var nonce = stackalloc byte[_nonceLen];
            *(ulong*)nonce = _inputSeqNumber++;
            *(int*)(nonce + sizeof(ulong)) = 0;
            for (var i = 0; i < _nonceLen / 2; i++)
            {
                var t = nonce[i];
                nonce[i] = nonce[_nonceLen - 1 - i];
                nonce[_nonceLen - 1 - i] = t;
            }

            for (var i = 0; i < _theirKeyMaterial.WriteIv.Length; i++)
                nonce[i] ^= _theirKeyMaterial.WriteIv[i];

            Span<byte> outputAuthTag = stackalloc byte[_authTagLen];

            _inputCipher.Decrypt(
                aad,
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input[..realDataLen],
                outputBuffer[..realDataLen],
                outputAuthTag);

            for (var i = 0; i < _authTagLen; i++)
                if (input[input.Length + i - _authTagLen] != outputAuthTag[i])
                    throw new InvalidOperationException("Incorrect Auth Tag");

            outputBuffer.Length = realDataLen;
            return outputBuffer;
        }

        public unsafe ArraySegment<byte> Encrypt(in ReadOnlySpan<byte> input, TlsContentType tlsContentType)
        {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
            // TLSInnerPlaintext
            var outputBuffer = new BigEndianWriteBuffer(input.Length + _authTagLen, true)
            {
                Length = input.Length + _authTagLen
            };

            // additional_data
            var inputLen = input.Length + _authTagLen;
            Span<byte> aad =
            [
                (byte)TlsContentType.ApplicationData,
                0x03, 0x03, // TlsVersion.Tls12
                (byte)(inputLen >> 8), (byte)inputLen
            ];

            var nonce = stackalloc byte[_nonceLen];
            *(ulong*)nonce = _outputSeqNumber++;
            *(int*)(nonce + sizeof(ulong)) = 0;
            for (var i = 0; i < _nonceLen / 2; i++)
            {
                var t = nonce[i];
                nonce[i] = nonce[_nonceLen - 1 - i];
                nonce[_nonceLen - 1 - i] = t;
            }

            for (var i = 0; i < _ourKeyMaterial.WriteIv.Length; i++)
                nonce[i] ^= _ourKeyMaterial.WriteIv[i];

            _outputCipher.Encrypt(
                aad,
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input,
                outputBuffer[..input.Length],
                outputBuffer[input.Length..]);

            return outputBuffer;
        }
    }
}
