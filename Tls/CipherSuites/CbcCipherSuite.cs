using System;
using System.Security.Cryptography;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.EllipticCryptography.WeierstrassForm.Signature;
using NiL.Cryptography.Encryption.Modes;
using NiL.Cryptography.Hashing;
using NiL.Cryptography.Signature;
using NiL.Cryptography.Tls.Tls12;
using NiL.Tools;

namespace NiL.Cryptography.Tls.CipherSuites;

public abstract class CbcCipherSuite : CipherSuiteBase
{
    // MAC generation
    // https://tools.ietf.org/html/rfc5246#section-6.2.3.1

    private const int _MacPrefixLen = sizeof(long) + sizeof(TlsContentType) + sizeof(TlsVersion) + sizeof(ushort);

    private readonly EcdhKeyDerivation _derivationAlgorithm;
    private readonly WeierstrassEcdsa _ecdsa;

    public override IPreMasterKeyDerivationAlgorithm KeyExchangeAlgorithm => _derivationAlgorithm;
    public override ISignatureAlgorithm SignatureAlgorithm => _ecdsa;
    public override PseudoRandomFunction PseudoRandomFunction { get; protected set; }

    public override TlsVersion[] TlsVersions { get; } = [TlsVersion.Tls12];

    protected CbcCipherSuite(WeierstrassEcdsa ecdsa, EcdhKeyDerivation masterKeyDerivationAlgorithm)
    {
        _derivationAlgorithm = masterKeyDerivationAlgorithm ?? throw new ArgumentNullException(nameof(masterKeyDerivationAlgorithm));
        _ecdsa = ecdsa ?? throw new ArgumentNullException(nameof(ecdsa));

        PseudoRandomFunction = new PseudoRandomFunction(Hmac, KeysSizes);
    }

    protected sealed class EncryptDecryptProcessor : IEncryptDecryptProcessor
    {
        public EncryptDecryptProcessor(TlsVersion tlsVersion, KeysSet12 keysSet, CbcMode outputCipher, CbcMode inputCipher, Hmac hmac)
        {
            _tlsVersion = tlsVersion;
            _keysSet = keysSet;
            _outputCipher = outputCipher ?? throw new ArgumentNullException(nameof(outputCipher));
            _inputCipher = inputCipher ?? throw new ArgumentNullException(nameof(inputCipher));
            _hmac = hmac;
            _randomGenerator = RandomNumberGenerator.Create();
        }

        private readonly RandomNumberGenerator _randomGenerator;
        private readonly TlsVersion _tlsVersion;
        private readonly KeysSet12 _keysSet;
        private readonly CbcMode _outputCipher;
        private readonly CbcMode _inputCipher;
        private readonly Hmac _hmac;
        private ulong _outputSeqNumber;
        private ulong _inputSeqNumber;

        // https://tools.ietf.org/html/rfc5246#section-6.2.3.2
        public unsafe ArraySegment<byte> Decrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType)
        {
            for (var i = 0; i < _inputCipher.IV.Length; i++)
                _inputCipher.IV[i] = inputBuffer[i];

            fixed (byte* inputPtr = &inputBuffer[_inputCipher.IV.Length])
            {
                var buffer = new Span<byte>(inputPtr, inputBuffer.Length - _inputCipher.IV.Length);

                var toMacBuffer = new BigEndianWriteBuffer(inputBuffer.Length + _MacPrefixLen, true);
                toMacBuffer.Uint64(_inputSeqNumber++);
                toMacBuffer.Uint8((byte)tlsContentType);
                toMacBuffer.Uint16((ushort)_tlsVersion);

                var outputBuffer = new Span<byte>(toMacBuffer.Buffer, _MacPrefixLen, inputBuffer.Length);

                _inputCipher.Decrypt(buffer, outputBuffer);

                var contentLength = inputBuffer.Length - _inputCipher.IV.Length;
                var paddingLen = outputBuffer[contentLength - 1];
                contentLength -= paddingLen + 1;
                contentLength -= _hmac.HashFunction.DigestSize;

                toMacBuffer.Uint16((ushort)contentLength);

                var mac = _hmac.Compute(new ArraySegment<byte>(toMacBuffer.Buffer, 0, _MacPrefixLen + contentLength), _keysSet.TheirWriteMacKey);

                for (var i = 0; i < mac.Length; i++)
                {
                    if (mac[i] != outputBuffer[i + contentLength])
                        throw new InvalidOperationException("Incorrect MAC");
                }

                return new ArraySegment<byte>(toMacBuffer.Buffer, _MacPrefixLen, contentLength);
            }
        }

        public ArraySegment<byte> Encrypt(in ReadOnlySpan<byte> inputBuffer, TlsContentType tlsContentType)
        {
            _randomGenerator.GetBytes(_outputCipher.IV);

            var workBuffer = new BigEndianWriteBuffer(_outputCipher.IV.Length + inputBuffer.Length + _outputCipher.OutBlockSize + _MacPrefixLen);
            workBuffer.Uint64(_outputSeqNumber++);
            workBuffer.Uint8((byte)tlsContentType);
            workBuffer.Uint16((ushort)_tlsVersion);
            workBuffer.Uint16((ushort)inputBuffer.Length);
            workBuffer.Bytes(inputBuffer);

            var mac = _hmac.Compute(new Span<byte>(workBuffer.Buffer, 0, workBuffer.Position), _keysSet.OurWriteMacKey);

            workBuffer.ResetSize();

            workBuffer.Bytes(_outputCipher.IV);
            workBuffer.Bytes(inputBuffer);
            workBuffer.Bytes(mac);

            var paddingSize = _outputCipher.OutBlockSize - ((inputBuffer.Length + mac.Length) % _outputCipher.OutBlockSize);
            var paddingValue = (byte)(paddingSize - 1);

            for (var i = 0; i < paddingSize; i++)
                workBuffer.Uint8(paddingValue);

            var segment = new Span<byte>(workBuffer.Buffer, _outputCipher.IV.Length, workBuffer.Position - _outputCipher.IV.Length);
            _outputCipher.Encrypt(segment, segment);

            var result = new ArraySegment<byte>(workBuffer.Buffer, 0, workBuffer.Position);

            return result;
        }
    }
}
