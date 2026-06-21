using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using NiL.Cryptography.EllipticCryptography;
using NiL.Cryptography.Tls.Extensions;
using NiL.Cryptography.Tls.Extensions.Renegotiation;
using NiL.Cryptography.Tls.Extensions.SignatureScheme;
using NiL.Cryptography.Tls.KeyExchange;
using NiL.Cryptography.Tls.Tls12;
using NiL.Cryptography.Tls.Tls13;
using NiL.Tools;

namespace NiL.Cryptography.Tls;

public partial class TlsSession
{
    private const int _maxRecordSize = 3 << 12; // for encription overhead

    private struct HandshakeRecord
    {
        public HandshakeType HandshakeType;
        public ArraySegment<byte>[] Data;
    }

    private BigEndianWriteBuffer _handshakeData;
    private TlsState _state;
    private KeyExchangeParams _keyExchangeParams;
    private KeysSet12 _keyset12;
    private EphemeralKeysSet _ephemeralKeysSet;
    private TlsContentType _lastReceivedContentType;
    private int _leftToRecieve;
    private IEncryptDecryptProcessor _encryptDecryptPair;
    private bool _tls12Encrypted;
    private KeySchedule _keySchedule;
    private readonly List<ITlsExtension> _clientExtensions;
    private readonly MemoryStream _recordsLayerInputStream;
    private readonly BigEndianStreamReader _srcReader;
    private readonly BigEndianStreamReader _internalReader;
    private readonly Socket _socket;
    private readonly BigEndianWriteBuffer _outputDataBuffer = new(1 << 12);

    public CipherSuiteBase CipherSuite { get; private set; }
    public CompressionMethod[] CompressionMethods { get; private set; }
    public CipherSuiteId[] ClientCipherSuites { get; private set; }
    public byte[] ClientSessionId { get; private set; }
    public PeerRandom ClientRandom { get; private set; }
    public PeerRandom ServerRandom { get; private set; }
    public TlsVersion TlsVersion { get; private set; }
    public TlsManager TlsManager { get; }
    public bool IsServerSide { get; }
    public TlsState State => _state;
    public string ApplicationLayerProtocol { get; private set; }
    public TlsStream TlsStream { get; set; }

    internal TlsSession(TlsManager tlsSessionManager, Socket socket, bool isServerSide)
    {
        if (socket is null)
            throw new ArgumentNullException(nameof(socket));

        TlsManager = tlsSessionManager;
        _socket = socket;
        IsServerSide = isServerSide;
        _recordsLayerInputStream = new MemoryStream(64);
        _srcReader = new BigEndianStreamReader(new NetworkStream(socket));
        _internalReader = new BigEndianStreamReader(_recordsLayerInputStream);
        TlsStream = new TlsStream(this);
        _clientExtensions = new();
        _handshakeData = new BigEndianWriteBuffer(1024);
    }

    public void Pump(int count, bool waitIncomming = false)
    {
        List<ArraySegment<byte>> segmentsToSend = null;

        lock (_outputDataBuffer)
        {
            _outputDataBuffer.ResetSize();

            for (; _socket.Available != 0 || count > 0; count--)
            {
                if (_leftToRecieve != 0)
                {
                    tryToReceiveRemainingBytes(waitIncomming);

                    if (_leftToRecieve != 0)
                        continue;
                }

                if (_recordsLayerInputStream.Position < _recordsLayerInputStream.Length)
                {
                    if (_encryptDecryptPair is not null && _lastReceivedContentType is not TlsContentType.Alert and not TlsContentType.ChangeCipherSpec)
                    {
                        var workBuffer = _recordsLayerInputStream.GetBuffer();
                        var encrypted = new ArraySegment<byte>(
                            workBuffer,
                            (int)_recordsLayerInputStream.Position,
                            (int)(_recordsLayerInputStream.Length - _recordsLayerInputStream.Position));

                        var decrypted = _encryptDecryptPair.Decrypt(encrypted, _lastReceivedContentType);

                        if (TlsVersion < TlsVersion.Tls13)
                        {
                            if (decrypted.Count < encrypted.Count)
                                _recordsLayerInputStream.SetLength(_recordsLayerInputStream.Length - encrypted.Count + decrypted.Count);

                            var decCount = decrypted.Count;
                            var decryptedBuffer = decrypted.Array;
                            var decOffset = decrypted.Offset;
                            var endOffset = encrypted.Offset;
                            for (var i = 0; i < decCount; i++)
                                workBuffer[endOffset + i] = decryptedBuffer[decOffset + i];
                        }
                        else
                        {
                            var dataSize = decrypted.Count - 1;

                            if (dataSize < encrypted.Count)
                                _recordsLayerInputStream.SetLength(_recordsLayerInputStream.Length - encrypted.Count + dataSize);

                            var endOffset = encrypted.Offset;
                            for (var i = 0; i < dataSize; i++)
                                workBuffer[endOffset + i] = decrypted[i];

                            _lastReceivedContentType = (TlsContentType)decrypted[dataSize];
                        }
                    }

                    var recordsToSend = processReceivedRecord(_lastReceivedContentType);

                    if (recordsToSend != null && recordsToSend.Length > 0)
                    {
                        if (segmentsToSend == null)
                            segmentsToSend = new List<ArraySegment<byte>>();

                        prepareRecordsForSend(segmentsToSend, recordsToSend);

                        if (_state == TlsState.CertificateSent && TlsVersion is TlsVersion.Tls13) // tls 1.3 finalization
                        {
                            prepareRecordsForSend(segmentsToSend, wrapHandshakeRecords([writeCertificateVerify()]));
                            prepareRecordsForSend(segmentsToSend, wrapHandshakeRecords([writeFinished()])); // CertificateVerify is using inside writeFinished()
                        }
                    }

                    if (_recordsLayerInputStream.Position == _recordsLayerInputStream.Length)
                        _recordsLayerInputStream.SetLength(0);
                }
                else if (!tryReadNextHeader(waitIncomming))
                    break;

                if (count > 1 && _socket.Available == 0)
                    Thread.Sleep(0);
            }

            if (segmentsToSend != null && segmentsToSend.Count > 0)
            {
                _socket.Send(segmentsToSend);
            }
        }
    }

    public void SendApplicationData(ArraySegment<byte> data)
    {
        if (data.Count == 0)
            return;

        lock (_outputDataBuffer)
        {
            _outputDataBuffer.ResetSize();

            // https://tools.ietf.org/html/rfc5246#section-6.2.1
            var recordsCount = (data.Count / _maxRecordSize) + (data.Count % _maxRecordSize != 0 ? 1 : 0);

            var outputRecordIndex = 0;

            var records = new TlsRecord[recordsCount];

            if (records.Length == 1)
            {
                records[0] = new TlsRecord
                {
                    Data = [data],
                    TlsContentType = TlsContentType.ApplicationData,
                    TlsVersion = TlsVersion
                };
            }
            else
            {
                var offset = 0;
                for (; outputRecordIndex < recordsCount; outputRecordIndex++)
                {
                    var dataChunkSize = Math.Min(data.Count - offset, _maxRecordSize);
                    var record = new TlsRecord
                    {
                        Data = [new ArraySegment<byte>(data.Array, data.Offset + offset, dataChunkSize)],
                        TlsContentType = TlsContentType.ApplicationData,
                        TlsVersion = TlsVersion,
                    };

                    offset += _maxRecordSize;

                    records[outputRecordIndex] = record;
                }
            }

            var segments = new List<ArraySegment<byte>>();
            prepareRecordsForSend(segments, records);
            _socket.Send(segments);
        }
    }

    public void SendAlert(Alert alert)
    {
        lock (_outputDataBuffer)
        {
            _outputDataBuffer.ResetSize();

            var data = new byte[2]
            {
                (byte)alert.Level,
                (byte)alert.Description,
            };

            var segments = new List<ArraySegment<byte>>();
            prepareRecordsForSend(segments,
            [
                new TlsRecord
                {
                    Data = [new ArraySegment<byte>(data)],
                    TlsContentType = TlsContentType.Alert,
                    TlsVersion = TlsVersion.Tls12,
                }
            ]);

            _socket.Send(segments);

            if (alert.Level == AlertLevel.Fatal)
                _socket.Close();
        }
    }

    private void prepareRecordsForSend(List<ArraySegment<byte>> segmentsToSend, TlsRecord[] recordsToSend)
    {
        var contentType = default(TlsContentType);
        var tlsVersion = default(TlsVersion);
        var recordSize = 0;
        var recordsGroupIndex = 0;
        var handshakeDataStart = _handshakeData?.Position;

        for (var i = 0; i < recordsToSend.Length + 1; i++)
        {
            var tlsRecord = i == recordsToSend.Length ? default : recordsToSend[i];

            if (recordSize != 0
                && (contentType != tlsRecord.TlsContentType
                    || recordSize + recordsToSend[i].Data.Length > _maxRecordSize
                    || tlsVersion != tlsRecord.TlsVersion
                    || (TlsVersion is TlsVersion.Tls13
                        && contentType == TlsContentType.Handshake
                        && recordsToSend[recordsGroupIndex].Data[0][0] == (byte)HandshakeType.ServerHello)))
            {
                if (contentType is TlsContentType.Handshake && _handshakeData is not null)
                {
                    for (var g = recordsGroupIndex; g < i; g++)
                    {
                        for (var j = 0; j < recordsToSend[g].Data.Length; j++)
                            _handshakeData.Bytes(recordsToSend[g].Data[j]);
                    }
                }

                var recordsChunk = new ArraySegment<TlsRecord>(recordsToSend, recordsGroupIndex, i - recordsGroupIndex);

                if (TlsVersion < TlsVersion.Tls13)
                {
                    prepareSegmentsForSend12(
                        recordsChunk,
                        segmentsToSend,
                        contentType,
                        tlsVersion,
                        recordSize);
                }
                else
                {
                    prepareSegmentsForSend13(
                        recordsChunk,
                        segmentsToSend,
                        contentType,
                        tlsVersion,
                        recordSize,
                        handshakeDataStart);
                }

                recordsGroupIndex = i;
                recordSize = 0;
                handshakeDataStart = _handshakeData?.Position;
            }

            if (tlsRecord.Data is null)
                break;

            contentType = tlsRecord.TlsContentType;
            tlsVersion = tlsRecord.TlsVersion;
            for (var j = 0; j < tlsRecord.Data.Length; j++)
                recordSize += tlsRecord.Data[j].Count;
        }
    }

    private void prepareSegmentsForSend13(
        ArraySegment<TlsRecord> recordsToSend,
        List<ArraySegment<byte>> segmentsToSend,
        TlsContentType contentType,
        TlsVersion tlsVersion,
        int recordSize,
        int? handshakeDataStart)
    {
        if (_encryptDecryptPair is not null)
        {
            ArraySegment<byte> encrypted;
            if (handshakeDataStart.HasValue)
            {
                _handshakeData.Uint8((byte)contentType);
                encrypted = _encryptDecryptPair.Encrypt(_handshakeData[handshakeDataStart.Value..], contentType);
                _handshakeData.Length = --_handshakeData.Position;
            }
            else
            {
                var plainPos = _outputDataBuffer.Position;
                for (var g = 0; g < recordsToSend.Count; g++)
                {
                    for (var j = 0; j < recordsToSend[g].Data.Length; j++)
                        _outputDataBuffer.Bytes(recordsToSend[g].Data[j]);
                }

                _outputDataBuffer.Uint8((byte)contentType);

                encrypted = _encryptDecryptPair.Encrypt(_outputDataBuffer[plainPos..], contentType);

                _outputDataBuffer.Position = plainPos;
                _outputDataBuffer.Length = plainPos;
            }

            _outputDataBuffer.Uint8((byte)TlsContentType.ApplicationData);
            _outputDataBuffer.Uint16((ushort)TlsVersion.Tls12);
            _outputDataBuffer.Uint16((ushort)encrypted.Count);

            segmentsToSend.Add(new ArraySegment<byte>(_outputDataBuffer.Buffer, _outputDataBuffer.Position - 5, 5));
            segmentsToSend.Add(encrypted);
        }
        else
        {
            _outputDataBuffer.Uint8((byte)contentType);
            _outputDataBuffer.Uint16((ushort)tlsVersion);
            _outputDataBuffer.Uint16((ushort)recordSize);
            segmentsToSend.Add(new ArraySegment<byte>(_outputDataBuffer.Buffer, _outputDataBuffer.Position - 5, 5));
            for (var g = 0; g < recordsToSend.Count; g++)
            {
                for (var j = 0; j < recordsToSend[g].Data.Length; j++)
                    segmentsToSend.Add(recordsToSend[g].Data[j]);
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc8446#section-5.1
        if (contentType == TlsContentType.Handshake
            && recordsToSend[0].Data[0][0] == (byte)HandshakeType.ServerHello)
        {
            if (TlsManager.SendFictiveChangeCipherSpec)
            {
                _outputDataBuffer.Uint8((byte)TlsContentType.ChangeCipherSpec);
                _outputDataBuffer.Uint16((ushort)TlsVersion.Tls12);
                _outputDataBuffer.Uint16(1);
                _outputDataBuffer.Uint8(1);
                segmentsToSend.Add(new ArraySegment<byte>(_outputDataBuffer.Buffer, _outputDataBuffer.Position - 6, 6));
            }

            _keySchedule.HandshakeKeys = CipherSuite.KeyScheduleDerivation.DeriveHandshakeKeys(_keySchedule.EarlyKeys, _ephemeralKeysSet.PreMasterKey, _handshakeData);
            _ephemeralKeysSet = null;
            var serverKeyMaterial = CipherSuite.KeyScheduleDerivation.DeriveTrafficKeyingMaterial(_keySchedule.HandshakeKeys.ServerHandshakeTrafficSecret);
            var clientKeyMaterial = CipherSuite.KeyScheduleDerivation.DeriveTrafficKeyingMaterial(_keySchedule.HandshakeKeys.ClientHandshakeTrafficSecret);

            _encryptDecryptPair = IsServerSide
                ? CipherSuite.CreateEncryptDecryptPair(serverKeyMaterial, clientKeyMaterial, TlsVersion)
                : CipherSuite.CreateEncryptDecryptPair(clientKeyMaterial, serverKeyMaterial, TlsVersion);
        }
    }

    private void prepareSegmentsForSend12(
        ArraySegment<TlsRecord> recordsToSend,
        List<ArraySegment<byte>> segmentsToSend,
        TlsContentType contentType,
        TlsVersion tlsVersion,
        int recordSize)
    {
        var buffer = _outputDataBuffer;
        if (_tls12Encrypted)
        {
            for (var g = 0; g < recordsToSend.Count; g++)
            {
                var startPos = buffer.Position;

                for (var j = 0; j < recordsToSend[g].Data.Length; j++)
                    buffer.Bytes(recordsToSend[g].Data[j]);

                var encrypted = _encryptDecryptPair.Encrypt(
                    new ArraySegment<byte>(buffer.Buffer, startPos, buffer.Position - startPos),
                    contentType);

                buffer.Uint8((byte)contentType);
                buffer.Uint16((ushort)tlsVersion);
                buffer.Uint16((ushort)encrypted.Count);
                segmentsToSend.Add(new ArraySegment<byte>(buffer.Buffer, buffer.Position - 5, 5));
                segmentsToSend.Add(encrypted);
            }
        }
        else
        {
            buffer.Uint8((byte)contentType);
            buffer.Uint16((ushort)tlsVersion);
            buffer.Uint16((ushort)recordSize);
            segmentsToSend.Add(new ArraySegment<byte>(buffer.Buffer, buffer.Position - 5, 5));

            for (var g = 0; g < recordsToSend.Count; g++)
            {
                for (var j = 0; j < recordsToSend[g].Data.Length; j++)
                    segmentsToSend.Add(recordsToSend[g].Data[j]);
            }
        }

        if (contentType == TlsContentType.ChangeCipherSpec)
            _tls12Encrypted = true;
    }

    private TlsRecord[] processReceivedRecord(TlsContentType contentType)
    {
        var remains = _recordsLayerInputStream.Length;
        var isRecordComplete = true;
        TlsRecord[] recordsToSend = null;
        while (remains > 0)
        {
            var oldPosition = _internalReader.Position;

            TlsRecord[] tlsRecords = null;
            switch (contentType)
            {
                case TlsContentType.Handshake:
                    isRecordComplete = processHandshake(_internalReader, out tlsRecords);
                    break;

                case TlsContentType.Alert:
                    isRecordComplete = processAlert(_internalReader);
                    break;

                case TlsContentType.ChangeCipherSpec:
                    isRecordComplete = processChangeCipherSpec(out tlsRecords);
                    break;

                case TlsContentType.ApplicationData:
                    if (_state < TlsState.Ready)
                        raiseUnexpectedMessage(contentType);

                    var buffer = _internalReader.Bytes(_internalReader.AvailableBytes);
                    TlsStream.EnqueueApplicationData(buffer);
                    break;

                default:
                    throw new NotImplementedException(contentType.ToString());
            }

            if (tlsRecords != null)
            {
                if (recordsToSend == null)
                {
                    recordsToSend = tlsRecords;
                }
                else
                {
                    Array.Resize(ref recordsToSend, recordsToSend.Length + tlsRecords.Length);
                    var bias = recordsToSend.Length - tlsRecords.Length;
                    for (var i = 0; i < tlsRecords.Length; i++)
                    {
                        recordsToSend[bias + i] = tlsRecords[i];
                    }
                }
            }

            if (!isRecordComplete)
            {
                _internalReader.Position = oldPosition;
                return recordsToSend;
            }

            remains -= _internalReader.Position - oldPosition;
        }

        return recordsToSend;
    }

    private void raiseUnexpectedMessage(object contentType)
    {
        throw new InvalidOperationException("Unexpected content type in handshake workflow (" + contentType + ", " + _state + ")");
    }

    private bool processChangeCipherSpec(out TlsRecord[] tlsRecords)
    {
        if (_internalReader.AvailableBytes < 1)
        {
            tlsRecords = null;
            return false;
        }

        if (_internalReader.UInt8() != 0x01)
            throw new InvalidDataException();

        if (TlsVersion < TlsVersion.Tls13)
        {
            if (_state == TlsState.ClientKeyExchangeGot)
                _state = TlsState.CipherSpecChangeGot;
            else
                raiseUnexpectedMessage(TlsContentType.ChangeCipherSpec);
        }
        else
        {
            if (_state != TlsState.FinishedSent)
                raiseUnexpectedMessage(TlsContentType.ChangeCipherSpec);
        }

        if (TlsVersion is TlsVersion.Tls13)
        {
            tlsRecords = [];
            return true;
        }

        _encryptDecryptPair = CipherSuite.CreateEncryptDecryptPair(_keyset12, TlsVersion);

        if (!isFalseStartAvailable())
        {
            tlsRecords = [changeCipherSpecRecord()];
        }
        else
        {
            tlsRecords = Array.Empty<TlsRecord>();
        }

        return true;
    }

    private static TlsRecord changeCipherSpecRecord()
    {
        return new TlsRecord
        {
            TlsContentType = TlsContentType.ChangeCipherSpec,
            TlsVersion = TlsVersion.Tls12,
            Data = [new ArraySegment<byte>([1])]
        };
    }

    private bool tryReadNextHeader(bool wait)
    {
        if (_socket.Available < 5 && !wait)
            return false;

        var contentType = (TlsContentType)_srcReader.UInt8();
        var tlsVersion = (TlsVersion)_srcReader.UInt16();

        //if (tlsVersion != TlsVersion.Tls12) // chrome шлёт tls1.0
        //    throw new NotSupportedException(tlsVersion.ToString());

        _lastReceivedContentType = contentType;
        _leftToRecieve = _srcReader.UInt16();

        return true;
    }

    private void tryToReceiveRemainingBytes(bool wait)
    {
        if (_leftToRecieve != 0)
        {
            var received = (int)_recordsLayerInputStream.Length;

            if (received + _leftToRecieve > _recordsLayerInputStream.Length)
                _recordsLayerInputStream.Capacity = received + _leftToRecieve;

            var inputBuffer = _recordsLayerInputStream.GetBuffer();
            var client = _socket;
            while (_leftToRecieve != 0 && (client.Available != 0 || wait))
            {
                var toReceive = Math.Min(_leftToRecieve, client.Available);
                if (toReceive == 0 && wait)
                    toReceive = 1;

                _recordsLayerInputStream.SetLength(received + toReceive);

                toReceive = client.Receive(inputBuffer, received, toReceive, SocketFlags.None);
                if (toReceive == 0)
                    throw new EndOfStreamException();

                received += toReceive;
                _leftToRecieve -= toReceive;
            }
        }
    }

    private HandshakeRecord writeKeyExchange()
    {
        switch (CipherSuite.KeyExchangeAlgorithm.Id)
        {
            // https://tools.ietf.org/html/rfc4492#section-5.4
            // https://tools.ietf.org/html/rfc8422#section-5.4
            case KeyExchangeAlgorithm.ECDH_ECDSA:
            {
                var ecdhParams = new BigEndianWriteBuffer(256);

                var curve = (CipherSuite.KeyExchangeAlgorithm as IEllipticCurveProvider).CurveDefinition;

                // ECParameters
                if (curve.Name != NamedCurve.Unnamed)
                {
                    ecdhParams.Uint8((byte)CurveType.NamedCurve);
                    ecdhParams.Uint16((ushort)curve.Name);
                }
                else
                    throw new NotImplementedException();

                _ephemeralKeysSet = CipherSuite.KeyExchangeAlgorithm.DeriveEphemeralKeys(null);

                // ECPoint
                ecdhParams.Uint8((byte)_ephemeralKeysSet.PublicKey.Length);
                ecdhParams.Bytes(_ephemeralKeysSet.PublicKey);

                // Signature
                var dataForSign = new BigEndianWriteBuffer(32 + 32 + ecdhParams.Length, true);
                dataForSign.Bytes(ClientRandom.Opaque);
                dataForSign.Bytes(ServerRandom.Opaque);
                dataForSign.Append(ecdhParams);

                var signature = CipherSuite.SignatureAlgorithm.Sign(dataForSign.Buffer);

                ecdhParams.Uint16((ushort)CipherSuite.SignatureAlgorithm.Id);
                ecdhParams.Uint16((ushort)signature.Length);
                ecdhParams.Bytes(signature);

                _state = TlsState.ServerKeyExchangeSent;

                return new HandshakeRecord
                {
                    HandshakeType = HandshakeType.ServerKeyExchange,
                    Data = [new ArraySegment<byte>(ecdhParams.Buffer, 0, ecdhParams.Length)]
                };
            }

            default: throw new NotImplementedException();
        }
    }

    private void selectCipherSuite(SupportedGroupsExtension supportedGroupsExtension, SignatureSchemesExtension signatureSchemesExtension)
    {
        for (var i = 0; i < TlsManager.CipherSuites.Length; i++)
        {
            var serverChipherSuite = TlsManager.CipherSuites[i];
            var curveId = (serverChipherSuite.KeyExchangeAlgorithm as IEllipticCurveProvider).CurveDefinition.Name;

            var isTls12Allowed = TlsManager.IsTls12Enabled && serverChipherSuite.TlsVersions.Contains(TlsVersion.Tls12);
            var isTls13Allowed = TlsManager.IsTls13Enabled && serverChipherSuite.TlsVersions.Contains(TlsVersion.Tls13);

            if (!isTls12Allowed && !isTls13Allowed)
                continue;

            for (var j = 0; j < ClientCipherSuites.Length; j++)
            {
                if (ClientCipherSuites[j] == TlsManager.CipherSuites[i].CipherSuiteId
                    && signatureSchemesExtension.Items.Contains(TlsManager.CipherSuites[i].SignatureAlgorithm.Id)
                    //&& TlsManager.CipherSuites[i].TlsVersions.Contains(TlsVersion)
                    && supportedGroupsExtension is not null && supportedGroupsExtension.NamedGroups.Contains(curveId))
                {
                    CipherSuite = serverChipherSuite;
                    return;
                }
            }
        }
    }

    private void selectApplicationLayerProtocol()
    {
        var alpn = _clientExtensions.OfType<ApplicationLayerProtocolNegotiationExtension>().FirstOrDefault();
        if (alpn != null)
        {
            foreach (var protocol in alpn.Protocols)
            {
                if (TlsManager.ApplicationLayerProtocols.Contains(protocol))
                {
                    ApplicationLayerProtocol = protocol;
                    break;
                }
            }
        }
    }

    private void generateServerRandom()
    {
        var buffer = new byte[32];
        RandomNumberGenerator.Create().GetBytes(buffer);

        if (TlsVersion == TlsVersion.Tls12 && TlsManager.IsTls13Enabled)
        {
            /* 44 4F 57 4E 47 52 44 01 */
            buffer[24] = 0x44;
            buffer[25] = 0x4F;
            buffer[26] = 0x57;
            buffer[27] = 0x4E;
            buffer[28] = 0x47;
            buffer[29] = 0x52;
            buffer[30] = 0x44;
            buffer[31] = 0x01;
        }

        var serverRandom = new PeerRandom(buffer);
        ServerRandom = serverRandom;
    }

    private HandshakeRecord writeServerHelloDone()
    {
        _state = TlsState.ServerHelloDoneSent;
        return new HandshakeRecord
        {
            HandshakeType = HandshakeType.ServerHelloDone,
            Data = [new ArraySegment<byte>(Array.Empty<byte>())]
        };
    }

    private HandshakeRecord writeCertificate()
    {
        if (TlsVersion is TlsVersion.Tls13)
        {
            var size = (uint)TlsManager.CertChainBinary.Sum(x => x.Length + 2);
            var bytes = new byte[5];
            bytes[4] = (byte)(size);
            bytes[3] = (byte)(size >> 8);
            bytes[2] = (byte)(size >> 16);

            _state = TlsState.CertificateSent;

            return new HandshakeRecord
            {
                HandshakeType = HandshakeType.Certificate,
                Data =
                [
                    new ArraySegment<byte>(bytes, 1, 4), // certificate_request_context=0, certificate_list=size (24 bits)
                    ..TlsManager.CertChainBinary.SelectMany(x => new[]{ new ArraySegment<byte>(x), new ArraySegment<byte>(bytes, 0, 2) }),
                ]
            };
        }
        else
        {
            var size = (uint)TlsManager.CertChainBinary.Sum(x => x.Length);
            var bytes = new byte[3];
            bytes[2] = (byte)(size);
            bytes[1] = (byte)(size >> 8);
            bytes[0] = (byte)(size >> 16);

            _state = TlsState.CertificateSent;

            return new HandshakeRecord
            {
                HandshakeType = HandshakeType.Certificate,
                Data = [bytes, .. TlsManager.CertChainBinary]
            };
        }
    }

    private HandshakeRecord writeCertificateVerify()
    {
        var contextString = IsServerSide ? "TLS 1.3, server CertificateVerify" : "TLS 1.3, client CertificateVerify";

        var dataForSign = new BigEndianWriteBuffer(64 + contextString.Length + 1 + CipherSuite.HashFunction.DigestSize, true);

        for (var i = 0; i < 64; i++)
            dataForSign.Uint8(0x20);

        for (var i = 0; i < contextString.Length; i++)
            dataForSign.Uint8((byte)contextString[i]);

        dataForSign.Uint8(0);

        dataForSign.Bytes(CipherSuite.HashFunction.Compute(_handshakeData));

        var signature = CipherSuite.SignatureAlgorithm.Sign(dataForSign.Buffer);

        var contentBuf = new BigEndianWriteBuffer(signature.Length + 4, true);
        contentBuf.Uint16((ushort)CipherSuite.SignatureAlgorithm.Id);
        contentBuf.Uint16((ushort)signature.Length);
        contentBuf.Bytes(signature);

        return new HandshakeRecord
        {
            HandshakeType = HandshakeType.CertificateVerify,
            Data = [new ArraySegment<byte>(contentBuf.Buffer, 0, contentBuf.Length)]
        };
    }

    private HandshakeRecord writeServerHello()
    {
        BigEndianWriteBuffer contentBuf = new BigEndianWriteBuffer(64);

        // content https://tools.ietf.org/html/rfc5246#section-7.4.1.3
        contentBuf.Uint16((ushort)TlsVersion.Tls12); // even for Tls 1.3

        var serverRandom = ServerRandom;
        contentBuf.Bytes(serverRandom.Opaque);

        if (TlsVersion is TlsVersion.Tls13)
        {
            contentBuf.Uint8((byte)ClientSessionId.Length);
            contentBuf.Bytes(ClientSessionId);
        }
        else
            contentBuf.Uint8(0);

        contentBuf.Uint16((ushort)CipherSuite.CipherSuiteId);
        contentBuf.Uint8((byte)CompressionMethod.None);

        var extensionsBuffer = new BigEndianWriteBuffer();

        if (TlsVersion < TlsVersion.Tls13)
        {
            var renegotiationInfo = _clientExtensions.OfType<RenegotiationExtension>().FirstOrDefault();
            var isSecureRenegotiationNeeded = ClientCipherSuites.Contains(CipherSuiteId.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
            if (renegotiationInfo != null)
            {
                if (renegotiationInfo.RenegotiationInfo.Info.Length == 0) // secure renegotiation
                {
                    isSecureRenegotiationNeeded = true;
                }
                else
                {
                    // obsolete
                }
            }

            if (isSecureRenegotiationNeeded)
            {
                extensionsBuffer.Uint16((ushort)ExtensionType.Renegotiation);
                extensionsBuffer.Uint16(1);
                extensionsBuffer.Uint8(0);
            }
        }

        if (TlsVersion == TlsVersion.Tls13)
        {
            var selectedGroupId = (CipherSuite.KeyExchangeAlgorithm as IEllipticCurveProvider).CurveDefinition.Name;

            (NamedCurve curve, byte[] key) keyShareData = default;

            var clientSupporedGroups = _clientExtensions.OfType<SupportedGroupsExtension>().First();
            var clientKeyShare = _clientExtensions.OfType<KeyShareExtension>().First();

            for (int i = 0; i < clientSupporedGroups.NamedGroups.Length; i++)
            {
                if (clientSupporedGroups.NamedGroups[i] == selectedGroupId)
                {
                    _keyExchangeParams = clientKeyShare.KeyExchangeParams.First(x => x.NamedCurve == selectedGroupId);

                    _ephemeralKeysSet = CipherSuite.KeyExchangeAlgorithm.DeriveEphemeralKeys(_keyExchangeParams);
                    keyShareData = (clientSupporedGroups.NamedGroups[i], _ephemeralKeysSet.PublicKey);

                    _keySchedule ??= new();
                    _keySchedule.EarlyKeys = CipherSuite.KeyScheduleDerivation.DeriveEarlyKeys(_handshakeData, false);
                    break;
                }
            }

            if (keyShareData.key is null)
                throw new NotImplementedException();

            // old versions of openssl does not permit this extension in ServerHello
#if false
            SupportedGroupsExtension.Write(
                extensionsBuffer,
                TlsManager
                    .CipherSuites
                    .Select(x => (x.KeyExchangeAlgorithm as IEllipticCurveProvider)?.CurveDefinition.Name)
                    .Where(x => x.HasValue)
                    .Select(x => x.Value)
                    .Distinct()
                    .ToArray());
#endif

            SupportedVersionsExtension.Write(extensionsBuffer, ExtensionContext.ServerHello, TlsVersion);
            KeyShareExtension.Write(extensionsBuffer, [keyShareData], ExtensionContext.ServerHello);
        }
        else if (ApplicationLayerProtocol is not null)
            ApplicationLayerProtocolNegotiationExtension.WriteSelected(ApplicationLayerProtocol, extensionsBuffer);

        if (extensionsBuffer.Length != 0)
        {
            contentBuf.Uint16((ushort)extensionsBuffer.Length);
            contentBuf.Append(extensionsBuffer);
        }

        _state = TlsState.ServerHelloSent;
        return new HandshakeRecord
        {
            HandshakeType = HandshakeType.ServerHello,
            Data = [new ArraySegment<byte>(contentBuf.Buffer, 0, contentBuf.Length)]
        };
    }

    private bool processAlert(BigEndianStreamReader read)
    {
        if (read.AvailableBytes < 2)
            return false;

        var level = (AlertLevel)read.UInt8();
        var desc = (AlertDescription)read.UInt8();

        if (level == AlertLevel.Fatal)
            throw new InvalidOperationException("Fatal allert: " + desc);

        return true;
    }

    private bool processHandshake(BigEndianStreamReader read, out TlsRecord[] recordsToSend)
    {
        // Handshake https://tools.ietf.org/html/rfc5246#section-7.4

        var startPos = (int)_recordsLayerInputStream.Position;

        var receivedHandshakeType = (HandshakeType)read.UInt8();
        var len = (int)read.UInt24();

        recordsToSend = null;

        if (read.AvailableBytes < len)
        {
            _recordsLayerInputStream.Position = startPos;
            return false;
        }

        _handshakeData.Bytes(new ReadOnlySpan<byte>(_recordsLayerInputStream.GetBuffer(), startPos, len + 4));

        switch (receivedHandshakeType)
        {
            case HandshakeType.ClientHello:
            {
                recordsToSend = wrapHandshakeRecords(processClientHello(read));

                if (TlsVersion < TlsVersion.Tls13 && isFalseStartAvailable())
                {
                    Array.Resize(ref recordsToSend, recordsToSend == null ? 1 : recordsToSend.Length + 1);
                    recordsToSend[^1] = changeCipherSpecRecord();
                }

                break;
            }

            case HandshakeType.ClientKeyExchange:
            {
                processClientKeyExchange(read);
                break;
            }

            case HandshakeType.Finished:
            {
                recordsToSend = wrapHandshakeRecords(processFinished(read, len));
                break;
            }

            default:
                throw new NotImplementedException(receivedHandshakeType.ToString());
        }

        return true;
    }

    private TlsRecord[] wrapHandshakeRecords(HandshakeRecord[] records)
    {
        TlsRecord[] outputTlsRecords = TlsVersion is TlsVersion.Tls13 ? new TlsRecord[records.Length] : new TlsRecord[1];
        var buffer = new BigEndianWriteBuffer(records.Length * 4, true);
        var outputBuffers = new List<ArraySegment<byte>>(records.Sum(x => x.Data.Length) + records.Length);
        for (var i = 0; i < records.Length; i++)
        {
            var data = records[i].Data;
            var recordLen = data.Sum(x => x.Count);

            var start = buffer.Position;

            var bufIndexStart = outputBuffers.Count;

            buffer.Uint8((byte)records[i].HandshakeType);
            buffer.Uint24((uint)recordLen);

            outputBuffers.Add(new ArraySegment<byte>(buffer.Buffer, start, 4));
            for (var j = 0; j < data.Length; j++)
                outputBuffers.Add(data[j]);

            if (TlsVersion is TlsVersion.Tls13)
            {
                outputTlsRecords[i] = new TlsRecord
                {
                    TlsContentType = TlsContentType.Handshake,
                    TlsVersion = TlsVersion.Tls12,
                    Data = outputBuffers.ToArray()
                };

                outputBuffers.Clear();
            }
        }

        if (TlsVersion is not TlsVersion.Tls13)
        {
            outputTlsRecords[0] = new TlsRecord
            {
                TlsContentType = TlsContentType.Handshake,
                TlsVersion = TlsVersion.Tls12,
                Data = outputBuffers.ToArray()
            };
        }

        return outputTlsRecords;
    }

    private HandshakeRecord writeFinished()
    {
        var handshakeHash = CipherSuite.HashFunction.Compute(_handshakeData);
        byte[] verifyData;
        if (TlsVersion < TlsVersion.Tls13)
        {
            verifyData = CipherSuite.PseudoRandomFunction.DeriveKey(
                _keyset12.MasterSecret,
                "server finished",
                handshakeHash,
                12);

            _handshakeData = null;
            _state = TlsState.Ready;
        }
        else
        {
            var finishedKey = CipherSuite.KeyScheduleDerivation.DeriveFinishedKey(IsServerSide, _keySchedule.HandshakeKeys);
            verifyData = CipherSuite.Hmac.Compute(handshakeHash, finishedKey);
            _state = TlsState.FinishedSent;
        }

        return new HandshakeRecord
        {
            HandshakeType = HandshakeType.Finished,
            Data = [new ArraySegment<byte>(verifyData)]
        };
    }

    // https://tools.ietf.org/html/rfc5246#section-7.4.9
    private HandshakeRecord[] processFinished(BigEndianStreamReader read, int len)
    {
        if (_handshakeData == null)
        {
            SendAlert(new Alert
            {
                Description = AlertDescription.Unexpected_message,
                Level = AlertLevel.Fatal
            });
            return [];
        }

        var handshakeHash = CipherSuite.HashFunction.Compute(_handshakeData[..^(len + 4)]);
        byte[] verifyData;
        if (TlsVersion < TlsVersion.Tls13)
        {
            if (_state is not TlsState.CipherSpecChangeGot)
                raiseUnexpectedMessage(TlsContentType.Handshake + "(" + HandshakeType.Finished + ")");

            verifyData = CipherSuite.PseudoRandomFunction.DeriveKey(
                _keyset12.MasterSecret,
                "client finished",
                handshakeHash,
                len);
        }
        else
        {
            if (_state is not TlsState.FinishedSent)
                raiseUnexpectedMessage(TlsContentType.Handshake + "(" + HandshakeType.Finished + ")");

            var finishedKey = CipherSuite.KeyScheduleDerivation.DeriveFinishedKey(!IsServerSide, _keySchedule.HandshakeKeys);
            verifyData = CipherSuite.Hmac.Compute(handshakeHash, finishedKey);
        }

        for (var i = 0; i < len; i++)
        {
            if (read.UInt8() != verifyData[i])
                throw new InvalidOperationException("client finished signature is invalid");
        }

        if (TlsVersion is TlsVersion.Tls13)
        {
            _keySchedule.MasterKeys = CipherSuite.KeyScheduleDerivation.DeriveMasterKeys(_keySchedule.HandshakeKeys, handshakeHash, true);
            var serverKeyMaterial = CipherSuite.KeyScheduleDerivation.DeriveTrafficKeyingMaterial(_keySchedule.MasterKeys.ServerApplicationTrafficSecret0);
            var clientKeyMaterial = CipherSuite.KeyScheduleDerivation.DeriveTrafficKeyingMaterial(_keySchedule.MasterKeys.ClientApplicationTrafficSecret0);

            var (ourKeyMaterial, theirKeyMaterial) = IsServerSide
                ? (serverKeyMaterial, clientKeyMaterial)
                : (clientKeyMaterial, serverKeyMaterial);

            _encryptDecryptPair = CipherSuite.CreateEncryptDecryptPair(ourKeyMaterial, theirKeyMaterial, TlsVersion);

            _handshakeData = null;
            _state = TlsState.Ready;

            return [];
        }
        else
        {
            return [writeFinished()];
        }
    }

    private void processClientKeyExchange(BigEndianStreamReader read)
    {
        if (TlsVersion >= TlsVersion.Tls13)
        {
            SendAlert(new()
            {
                Description = AlertDescription.Unexpected_message,
                Level = AlertLevel.Fatal,
            });
            throw new InvalidOperationException(AlertDescription.Unexpected_message.ToString());
        }

        if (_state is not TlsState.ServerHelloDoneSent)
            raiseUnexpectedMessage(TlsContentType.Handshake + "(" + HandshakeType.ClientKeyExchange + ")");

        var length = read.UInt8();
        var otherSidePublic = read.Bytes(length);
        var preMasterKey = CipherSuite.KeyExchangeAlgorithm.DerivePreMasterKey(otherSidePublic, _ephemeralKeysSet.PrivateKey);
        _ephemeralKeysSet = null;
        _keyset12 = CipherSuite.PseudoRandomFunction.DeriveKeySet(preMasterKey, ServerRandom.Opaque, ClientRandom.Opaque, IsServerSide);
        _state = TlsState.ClientKeyExchangeGot;
    }

    private HandshakeRecord[] processClientHello(BigEndianStreamReader read)
    {
        // ClientHello https://tools.ietf.org/html/rfc5246#section-7.4.1.2

        if (_state != TlsState.Initial)
            raiseUnexpectedMessage(HandshakeType.ClientHello + " at " + _state);

        TlsVersion = (TlsVersion)read.UInt16();

        var random = new PeerRandom(read.Bytes(32));

        ClientRandom = random;

        var sessionIdLen = read.UInt8();
        if (sessionIdLen > 32)
            throw new InvalidOperationException();

        var sessionId = read.Bytes(sessionIdLen);

        ClientSessionId = sessionId;

        var cipherSuiteLen = read.UInt16();
        var cipherSuites = new CipherSuiteId[cipherSuiteLen / sizeof(CipherSuiteId)];
        for (var i = 0; i < cipherSuites.Length; i++)
        {
            cipherSuites[i] = (CipherSuiteId)read.UInt16();
        }

        ClientCipherSuites = cipherSuites;

        var compressionMethodsCount = read.UInt8();
        var compressionMethods = new CompressionMethod[compressionMethodsCount];
        for (var i = 0; i < compressionMethods.Length; i++)
        {
            compressionMethods[i] = (CompressionMethod)read.UInt8();
        }

        CompressionMethods = compressionMethods;

        if (read.AvailableBytes > 0)
        {
            var extensionsLen = read.UInt16();
            var start = read.Position;
            while (read.Position < start + extensionsLen)
            {
                _clientExtensions.Add(ExtensionsRegistry.ReadExtension(read, ExtensionContext.ClientHello));
            }
        }

        if (TlsVersion < TlsVersion.Tls12)
        {
            if (Array.IndexOf(ClientCipherSuites, CipherSuiteId.TLS_FALLBACK_SCSV) != -1)
            {
                SendAlert(new Alert
                {
                    Description = AlertDescription.Inappropriate_fallback,
                    Level = AlertLevel.Fatal,
                });
            }
            else
            {
                SendAlert(new Alert
                {
                    Description = AlertDescription.Protocol_version,
                    Level = AlertLevel.Fatal,
                });
            }

            return Array.Empty<HandshakeRecord>();
        }

        if (TlsManager.IsTls13Enabled)
        {
            var versionsExtension = _clientExtensions.OfType<SupportedVersionsExtension>().FirstOrDefault();
            if (versionsExtension != null)
            {
                if (versionsExtension.TlsVersions.Contains(TlsVersion.Tls13))
                {
                    TlsVersion = TlsVersion.Tls13;
                }
            }
        }

        selectCipherSuite(
            _clientExtensions.OfType<SupportedGroupsExtension>().FirstOrDefault(),
            _clientExtensions.OfType<SignatureSchemesExtension>().FirstOrDefault());

        if (CipherSuite == null || CipherSuite == null || CipherSuite.CipherSuiteId == CipherSuiteId.Unknown)
        {
            SendAlert(new Alert() { Description = AlertDescription.Handshake_failure, Level = AlertLevel.Fatal });
            throw new InvalidOperationException("No known cipher suite. Client cipher suites: " + string.Join(Environment.NewLine, ClientCipherSuites));
        }

        TlsVersion = CipherSuite.TlsVersions.Max();

        generateServerRandom();
        selectApplicationLayerProtocol();

        _state = TlsState.ClientHelloGot;

        if (TlsVersion == TlsVersion.Tls13)
        {
            return
            [
                writeServerHello(),
                writeEncryptedExtensions(),
                writeCertificate(),
            ];
        }
        else
        {
            return
            [
                writeServerHello(),
                writeCertificate(),
                writeKeyExchange(),
                writeServerHelloDone(),
            ];
        }
    }

    private HandshakeRecord writeEncryptedExtensions()
    {
        if (ApplicationLayerProtocol is null)
        {
            return new HandshakeRecord
            {
                HandshakeType = HandshakeType.EncryptedExtensions,
                Data =
                [
                    new byte[] { 0,0 },
                    []
                ]
            };
        }

        var extensionsBuffer = new BigEndianWriteBuffer();
        ApplicationLayerProtocolNegotiationExtension.WriteSelected(ApplicationLayerProtocol, extensionsBuffer);
        var len = extensionsBuffer.Length;
        return new HandshakeRecord
        {
            HandshakeType = HandshakeType.EncryptedExtensions,
            Data =
            [
                new[] { (byte)(len >> 8), (byte)len },
                extensionsBuffer
            ]
        };
    }

    private bool isFalseStartAvailable() => !string.IsNullOrWhiteSpace(ApplicationLayerProtocol);
}
