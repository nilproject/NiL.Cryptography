using System;
using System.Security.Cryptography;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Encryption.Modes.Gcm;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Tls.Tls12;
using NiL.Cryptography.Tls.Tls13;
using NiL.Tools;

namespace NiL.Cryptography.Tls.CipherSuites;

[CipherSuiteId(CipherSuiteId.TLS_AES_256_GCM_SHA384)]
public class TlsAes256GcmSha384 : TlsAes128GcmSha256
{
    public TlsAes256GcmSha384(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, 32, 12);
    }

    public override IHashFunction HashFunction => Sha384.Instance;
}

[CipherSuiteId(CipherSuiteId.TLS_AES_128_GCM_SHA256)]
public class TlsAes128GcmSha256 : EcdheEcdsaAes128GcmSha256
{
    public TlsAes128GcmSha256(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        PseudoRandomFunction = null;
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, 16, 12);
    }

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls13];

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(TrafficKeyingMaterial ourKeyMaterial, TrafficKeyingMaterial theirKeyMaterial, TlsVersion tlsVersion)
    {
        return new EncryptDecryptProcessor(
            tlsVersion,
            ourKeyMaterial,
            theirKeyMaterial,
            Hmac);
    }

    public sealed override IEncryptDecryptProcessor CreateEncryptDecryptPair12(KeysSet12 keysSet, TlsVersion tlsVersion)
        => throw new NotSupportedException();

    private sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private const int _nonceLen = 12;
        private const int _authTagLen = 16;

        private readonly GcmMode _outputCipher;
        private readonly GcmMode _inputCipher;
        private readonly TlsVersion _tlsVersion;
        private readonly TrafficKeyingMaterial _ourKeyMaterial;
        private readonly TrafficKeyingMaterial _theirKeyMaterial;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(TlsVersion tlsVersion, TrafficKeyingMaterial ourKeyMaterial, TrafficKeyingMaterial theirKeyMaterial, Hmac hmac)
        {
            if (ourKeyMaterial.WriteKey is null || theirKeyMaterial.WriteKey is null
                    || ourKeyMaterial.WriteIv is null || theirKeyMaterial.WriteIv is null)
                throw new ArgumentNullException();

            _outputCipher = new GcmMode(new Encryption.Aes(ourKeyMaterial.WriteKey));
            _inputCipher = new GcmMode(new Encryption.Aes(theirKeyMaterial.WriteKey));
            _hmac = hmac;
            _tlsVersion = tlsVersion;
            _ourKeyMaterial = ourKeyMaterial;
            _theirKeyMaterial = theirKeyMaterial;
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
            outputBuffer.Uint8((byte)TlsContentType.ApplicationData);
            outputBuffer.Uint16((ushort)TlsVersion.Tls12);
            outputBuffer.Uint16((ushort)input.Length);

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
                outputBuffer.Buffer[..5],
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
            outputBuffer.Uint8((byte)TlsContentType.ApplicationData);
            outputBuffer.Uint16((ushort)TlsVersion.Tls12);
            outputBuffer.Uint16((ushort)(input.Length + _authTagLen));

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
                outputBuffer[..5],
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input,
                outputBuffer[..input.Length],
                outputBuffer[input.Length..]);

            return outputBuffer;
        }
    }
}
