using System;
using System.Diagnostics;
using System.Security.Cryptography;
using NiL.Cryptography.Encryption;
using NiL.Cryptography.Hashing;
using NiL.Tools;

namespace NiL.Cryptography.Tls.CipherSuites;

public abstract class Tls12CipherSuiteBase : CipherSuiteBase
{
    private const int _explicitNonceLen = 8;
    private const int _authTagLen = 16;

    protected sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        private readonly KeysSet12 _keysSet;
        private readonly IAeadCipher _outputCipher;
        private readonly IAeadCipher _inputCipher;
        private readonly bool _alternativeNonceGeneration;
        private readonly TlsVersion _tlsVersion;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        public EncryptDecryptProcessor(
            TlsVersion tlsVersion,
            KeysSet12 keysSet,
            Hmac hmac,
            IAeadCipher outputCipher,
            IAeadCipher inputCipher,
            bool alternativeNonceGeneration)
        {
            if (keysSet.OurWriteKey is null || keysSet.TheirWriteKey is null
                    || keysSet.OurWriteIV is null || keysSet.TheirWriteIV is null)
                throw new ArgumentNullException();

            _keysSet = keysSet;
            _hmac = hmac;
            _tlsVersion = tlsVersion;
            _outputCipher = outputCipher;
            _inputCipher = inputCipher;
            _alternativeNonceGeneration = alternativeNonceGeneration;
        }

        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType)
        {
            var authBuffer = new BigEndianWriteBuffer(8 + 1 + 2 + 2, true);
            authBuffer.Uint64(_inputSeqNumber++);
            authBuffer.Uint8((byte)tlsContentType);
            authBuffer.Uint16((ushort)_tlsVersion);

            byte[] nonce;

            if (_alternativeNonceGeneration)
            {
                var nonceLen = _keysSet.TheirWriteIV.Length;
                nonce = new byte[nonceLen];

                for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                    nonce[i] = _keysSet.TheirWriteIV[i];

                for (var i = 0; i < 8; i++)
                    nonce[i + nonceLen - 8] ^= authBuffer.Buffer[i];
            }
            else
            {
                var nonceLen = _keysSet.TheirWriteIV.Length + _explicitNonceLen;
                nonce = new byte[nonceLen];

                for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                    nonce[i] = _keysSet.TheirWriteIV[i];

                for (var i = _keysSet.TheirWriteIV.Length; i < nonceLen; i++)
                    nonce[i] = inputBuffer[i - _keysSet.TheirWriteIV.Length];
            }

            var cipheredDataLen = inputBuffer.Length - (nonce.Length - _keysSet.TheirWriteIV.Length) - _authTagLen;

            authBuffer.Uint16((ushort)cipheredDataLen);

            var output = new byte[cipheredDataLen];
            var authTag = new byte[_authTagLen];

            fixed (byte* inputPtr = &inputBuffer[nonce.Length - _keysSet.TheirWriteIV.Length])
            {
                _inputCipher.Decrypt(
                    authBuffer,
                    nonce,
                    new Span<byte>(inputPtr, cipheredDataLen),
                    output,
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
            int nonceLen;
            byte[] nonce;

            if (_alternativeNonceGeneration)
            {
                nonceLen = _keysSet.TheirWriteIV.Length;
                nonce = new byte[nonceLen];

                for (var i = 0; i < _keysSet.TheirWriteIV.Length; i++)
                    nonce[i] = _keysSet.OurWriteIV[i];

                var seqNum = _outputSeqNumber;
                for (var i = 8; seqNum != 0 && i-- > 0; i++)
                {
                    nonce[i + nonceLen - 8] ^= (byte)seqNum;
                    seqNum >>= 8;
                }
            }
            else
            {
                nonceLen = _keysSet.TheirWriteIV.Length + _explicitNonceLen;
                nonce = new byte[nonceLen];

                for (var i = 0; i < _keysSet.OurWriteIV.Length; i++)
                    nonce[i] = _keysSet.OurWriteIV[i];

                var explicitNonce =
                    ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 48)
                    ^ ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 24)
                    ^ ((ulong)RandomNumberGenerator.GetInt32(int.MaxValue) << 0);

                var enp = (byte*)&explicitNonce;
                for (var i = _keysSet.OurWriteIV.Length; i < nonceLen; i++)
                    nonce[i] = enp[i - _keysSet.OurWriteIV.Length];

                outputBuffer.Bytes(new Span<byte>(nonce, _keysSet.TheirWriteIV.Length, _explicitNonceLen));
            }

            const int authDataLen = 8 + 1 + 2 + 2;
            var authData = new Span<byte>(outputBuffer.Buffer, nonceLen - _keysSet.TheirWriteIV.Length + inputBuffer.Length, authDataLen);

            // temporary reuse (AuthTagLen > authDataLen)
            outputBuffer.Length = nonceLen - _keysSet.TheirWriteIV.Length + inputBuffer.Length;
            outputBuffer.Position = outputBuffer.Length;
            outputBuffer.Uint64(_outputSeqNumber++);
            outputBuffer.Uint8((byte)tlsContentType);
            outputBuffer.Uint16((ushort)_tlsVersion);
            outputBuffer.Uint16((ushort)inputBuffer.Length);

            _outputCipher.Encrypt(
                authData,
                nonce,
                inputBuffer,
                new Span<byte>(outputBuffer.Buffer, nonceLen - _keysSet.TheirWriteIV.Length, inputBuffer.Length),
                new Span<byte>(outputBuffer.Buffer, nonceLen - _keysSet.TheirWriteIV.Length + inputBuffer.Length, _authTagLen));

            outputBuffer.Length += _authTagLen - authDataLen;

            Debug.Assert(
                outputBuffer.Length
                == nonceLen - _keysSet.TheirWriteIV.Length // explicit nonce
                + inputBuffer.Length // data
                + _authTagLen // auth tag
                );

            return outputBuffer;
        }
    }
}
