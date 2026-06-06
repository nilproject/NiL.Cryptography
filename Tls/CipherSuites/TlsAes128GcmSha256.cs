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

[CipherSuiteId(CipherSuiteId.TLS_AES_128_GCM_SHA256)]
public class TlsAes128GcmSha256 : EcdheEcdsaAes128GcmSha256
{
    public TlsAes128GcmSha256(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        PseudoRandomFunction = null;
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, 16, 12);
    }

    public override CipherSuiteId CipherSuiteId => CipherSuiteId.TLS_AES_128_GCM_SHA256;

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls13];

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion)
    {
        return new EncryptDecryptProcessor(
            tlsVersion,
            keysSet,
            new GcmMode(new Encryption.Aes(keysSet.OurWriteKey)),
            new GcmMode(new Encryption.Aes(keysSet.TheirWriteKey)),
            Hmac);
    }

    private sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private const int _nonceLen = 12;
        private const int _authTagLen = 16;

        private readonly KeysSet12 _keysSet;
        private readonly GcmMode _outputCipher;
        private readonly GcmMode _inputCipher;
        private readonly TlsVersion _tlsVersion;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(TlsVersion tlsVersion, KeysSet12 keysSet, GcmMode outputCipher, GcmMode inputCipher, Hmac hmac)
        {
            if (keysSet.OurWriteKey is null || keysSet.TheirWriteKey is null
                    || keysSet.OurWriteIV is null || keysSet.TheirWriteIV is null)
                throw new ArgumentNullException();

            _keysSet = keysSet;
            _outputCipher = outputCipher ?? throw new ArgumentNullException(nameof(outputCipher));
            _inputCipher = inputCipher ?? throw new ArgumentNullException(nameof(inputCipher));
            _hmac = hmac;
            _tlsVersion = tlsVersion;
        }

        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> input, TlsContentType tlsContentType)
        {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
            // TLSInnerPlaintext
            var realDataLen = input.Length - _authTagLen;
            var outputBuffer = new BigEndianWriteBuffer(Math.Max(5, realDataLen), true);
            outputBuffer.Length = realDataLen;

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

            for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                nonce[i] ^= _keysSet.TheirWriteIV[i];

            var outputAuthTag = stackalloc byte[_authTagLen];

            _inputCipher.Decrypt(
                outputBuffer.Buffer[..5],
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input[..realDataLen],
                outputBuffer[..realDataLen],
                new Span<byte>(outputAuthTag, _authTagLen));

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
            var outputBuffer = new BigEndianWriteBuffer(input.Length + _authTagLen, true);
            outputBuffer.Length = input.Length + _authTagLen;

            // additional_data
            outputBuffer.Uint8((byte)TlsContentType.ApplicationData);
            outputBuffer.Uint16((ushort)TlsVersion.Tls12);
            outputBuffer.Uint16((ushort)(input.Length + _authTagLen));

            var nonce = stackalloc byte[_nonceLen];
            *(ulong*)nonce = _outputSeqNumber++;
            *(int*)(nonce + sizeof(ulong)) = 0;
            for (var i = 0; i < _nonceLen / 2;i++)
            {
                var t = nonce[i];
                nonce[i] = nonce[_nonceLen - 1 - i];
                nonce[_nonceLen - 1 - i] = t;
            }

            for (var i = 0; i < _keysSet.OurWriteIV.Length; i++)
                nonce[i] ^= _keysSet.OurWriteIV[i];

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

[CipherSuiteId(CipherSuiteId.TLS_AES_128_GCM_SHA256)]
public class SystemTlsAes128GcmSha256 : EcdheEcdsaAes128GcmSha256
{
    public SystemTlsAes128GcmSha256(EcdhKeyDerivation keyDerivationAlgorithm, WeierstrassEcdsa ecdsa) : base(keyDerivationAlgorithm, ecdsa)
    {
        PseudoRandomFunction = null;
        KeyScheduleDerivation = new KeyScheduleDerivation(Hmac, 16, 12);
    }

    public override CipherSuiteId CipherSuiteId => CipherSuiteId.TLS_AES_128_GCM_SHA256;

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls13];

    public override IEncryptDecryptProcessor CreateEncryptDecryptPair(KeysSet12 keysSet, TlsVersion tlsVersion)
    {
        return new EncryptDecryptProcessor(
            tlsVersion,
            keysSet,
            new AesGcm(keysSet.OurWriteKey),
            new AesGcm(keysSet.TheirWriteKey),
            Hmac);
    }

    private sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private const int _nonceLen = 12;
        private const int _authTagLen = 16;

        private readonly KeysSet12 _keysSet;
        private readonly AesGcm _outputCipher;
        private readonly AesGcm _inputCipher;
        private readonly TlsVersion _tlsVersion;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(TlsVersion tlsVersion, KeysSet12 keysSet, AesGcm outputCipher, AesGcm inputCipher, Hmac hmac)
        {
            if (keysSet.OurWriteKey is null || keysSet.TheirWriteKey is null
                    || keysSet.OurWriteIV is null || keysSet.TheirWriteIV is null)
                throw new ArgumentNullException();

            _keysSet = keysSet;
            _outputCipher = outputCipher ?? throw new ArgumentNullException(nameof(outputCipher));
            _inputCipher = inputCipher ?? throw new ArgumentNullException(nameof(inputCipher));
            _hmac = hmac;
            _tlsVersion = tlsVersion;
        }

        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> input, TlsContentType tlsContentType)
        {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
            // TLSInnerPlaintext
            var realDataLen = input.Length - _authTagLen;
            var outputBuffer = new BigEndianWriteBuffer(Math.Max(5, realDataLen), true);
            outputBuffer.Length = realDataLen;

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

            for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                nonce[i] ^= _keysSet.TheirWriteIV[i];

            _inputCipher.Decrypt(
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input[..realDataLen],
                input.Slice(realDataLen, 12),
                outputBuffer[..realDataLen],
                outputBuffer.Buffer[..5]);

            outputBuffer.Length = realDataLen;
            return outputBuffer;
        }

        public unsafe ArraySegment<byte> Encrypt(in ReadOnlySpan<byte> input, TlsContentType tlsContentType)
        {
            // https://datatracker.ietf.org/doc/html/rfc8446#section-5.2
            // TLSInnerPlaintext
            var outputBuffer = new BigEndianWriteBuffer(input.Length + _authTagLen, true);
            outputBuffer.Length = input.Length + _authTagLen;

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

            for (var i = 0; i < _keysSet.OurWriteIV.Length; i++)
                nonce[i] ^= _keysSet.OurWriteIV[i];

            _outputCipher.Encrypt(
                new ReadOnlySpan<byte>(nonce, _nonceLen),
                input,
                outputBuffer[..input.Length],
                outputBuffer[input.Length..],
                outputBuffer[..5]);

            return outputBuffer;
        }
    }
}
