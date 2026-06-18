using System;
using System.Text;
using NiL.Cryptography.Hashing;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Tls13;
/*
 Derive-Secret(., "c e traffic", ClientHello)
             |                     = client_early_traffic_secret
             |
             +-----> Derive-Secret(., "e exp master", ClientHello)
             |                     = early_exporter_master_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   (EC)DHE -> HKDF-Extract = Handshake Secret
             |
             +-----> Derive-Secret(., "c hs traffic",
             |                     ClientHello...ServerHello)
             |                     = client_handshake_traffic_secret
             |
             +-----> Derive-Secret(., "s hs traffic",
             |                     ClientHello...ServerHello)
             |                     = server_handshake_traffic_secret
             v
       Derive-Secret(., "derived", "")
             |
             v
   0 -> HKDF-Extract = Master Secret
             |
             +-----> Derive-Secret(., "c ap traffic",
             |                     ClientHello...server Finished)
             |                     = client_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "s ap traffic",
             |                     ClientHello...server Finished)
             |                     = server_application_traffic_secret_0
             |
             +-----> Derive-Secret(., "exp master",
             |                     ClientHello...server Finished)
             |                     = exporter_master_secret
             |
             +-----> Derive-Secret(., "res master",
                                   ClientHello...client Finished)
                                   = resumption_master_secret
*/

// https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
// https://datatracker.ietf.org/doc/html/rfc5869
public class KeyScheduleDerivation
{
    private readonly HmacBasedKeyDerivationFunction _hkdf;
    private readonly byte[] _emptyContextHash;
    private readonly int _keyLength;
    private readonly int _ivLength;

    public KeyScheduleDerivation(Hmac hmac, int keyLength, int ivLength)
    {
        _hkdf = new HmacBasedKeyDerivationFunction(hmac);
        _emptyContextHash = _hkdf.Hmac.HashFunction.Compute([]);
        _keyLength = keyLength;
        _ivLength = ivLength;
    }

    public EarlyKeys DeriveEarlyKeys(scoped in ReadOnlySpan<byte> messages, bool isResumption)
    {
        var length = _hkdf.Hmac.HashFunction.DigestSize;
        byte[] preSharedKey = new byte[length];
        var transcriptHash = _hkdf.Hmac.HashFunction.Compute(messages);
        var earlySecret = _hkdf.HkdfExtract(null, preSharedKey);
        var binderKey = expandLabel(earlySecret, isResumption ? "res binder" : "ext binder", _emptyContextHash, length);
        var clientEarlyTrafficSecret = expandLabel(earlySecret, "c e traffic", transcriptHash, length);
        var earlyExporterMasterSecret = expandLabel(earlySecret, "e exp master", transcriptHash, length);
        var derived = expandLabel(earlySecret, "derived", _emptyContextHash, length);

        return new EarlyKeys(
            binderKey,
            clientEarlyTrafficSecret,
            earlyExporterMasterSecret,
            derived);
    }

    public HandshakeKeys DeriveHandshakeKeys(EarlyKeys earlyKeySchedule, byte[] dheKey, scoped in ReadOnlySpan<byte> messages)
    {
        var length = _hkdf.Hmac.HashFunction.DigestSize;
        var transcriptHash = _hkdf.Hmac.HashFunction.Compute(messages);
        var handshakeSecret = _hkdf.HkdfExtract(earlyKeySchedule.Derived, dheKey);
        var clientHandshakeTrafficSecret = expandLabel(handshakeSecret, "c hs traffic", transcriptHash, length);
        var serverHandshakeTrafficSecret = expandLabel(handshakeSecret, "s hs traffic", transcriptHash, length);
        var derived = expandLabel(handshakeSecret, "derived", _emptyContextHash, length);

        return new HandshakeKeys(
            clientHandshakeTrafficSecret,
            serverHandshakeTrafficSecret,
            derived);
    }

    public byte[] DeriveFinishedKey(bool isServer, HandshakeKeys handshakeKeySchedule)
    {
        return expandLabel(
            isServer ? handshakeKeySchedule.ServerHandshakeTrafficSecret : handshakeKeySchedule.ClientHandshakeTrafficSecret,
            "finished",
            Array.Empty<byte>(),
            _hkdf.Hmac.HashFunction.DigestSize);
    }

    public MasterKeys DeriveMasterKeys(HandshakeKeys earlyKeySchedule, scoped in ReadOnlySpan<byte> messages, bool isComputedMessagesHash)
    {
        var length = _hkdf.Hmac.HashFunction.DigestSize;
        var transcriptHash = isComputedMessagesHash ? messages : _hkdf.Hmac.HashFunction.Compute(messages);
        var handshakeSecret = _hkdf.HkdfExtract(earlyKeySchedule.Derived, new byte[length]);
        var clientApplicationTrafficSecret = expandLabel(handshakeSecret, "c ap traffic", transcriptHash, length);
        var serverApplicationTrafficSecret = expandLabel(handshakeSecret, "s ap traffic", transcriptHash, length);
        var exporterMasterSecret = expandLabel(handshakeSecret, "exp master", transcriptHash, length);
        var resumptionMasterSecret = expandLabel(handshakeSecret, "res master", transcriptHash, length);

        return new MasterKeys(
            clientApplicationTrafficSecret,
            serverApplicationTrafficSecret,
            exporterMasterSecret,
            resumptionMasterSecret);
    }

    public TrafficKeyingMaterial DeriveTrafficKeyingMaterial(byte[] secret)
    {
        var writeKey = expandLabel(
            secret,
            "key",
            Array.Empty<byte>(),
            _keyLength);

        var writeIv = expandLabel(
            secret,
            "iv",
            Array.Empty<byte>(),
            _ivLength);

        return new TrafficKeyingMaterial(writeKey, writeIv);
    }

    public KeysSet12 CreateKeySet12(TrafficKeyingMaterial ourKeyMaterial, TrafficKeyingMaterial theirKeyMaterial)
    {
        var keyset = new KeysSet12(null, new KeysSizes(0, _keyLength, _ivLength));

        Array.Copy(ourKeyMaterial.WriteKey, keyset.OurWriteKey, _keyLength);
        Array.Copy(theirKeyMaterial.WriteKey, keyset.TheirWriteKey, _keyLength);

        Array.Copy(ourKeyMaterial.WriteIv, keyset.OurWriteIV, _ivLength);
        Array.Copy(theirKeyMaterial.WriteIv, keyset.TheirWriteIV, _ivLength);

        return keyset;
    }

    private byte[] expandLabel(in ReadOnlySpan<byte> secret, string label, in ReadOnlySpan<byte> context, int length)
    {
        var hkdfLabel = new BigEndianWriteBuffer();
        hkdfLabel.Uint16((ushort)length);
        hkdfLabel.Uint8((byte)(6 + label.Length));
        hkdfLabel.Bytes(Encoding.ASCII.GetBytes("tls13 "));
        hkdfLabel.Bytes(Encoding.ASCII.GetBytes(label));
        hkdfLabel.Uint8((byte)context.Length);
        hkdfLabel.Bytes(context);

        return _hkdf.HkdfExpand(secret, hkdfLabel, length).ToArray();
    }
}
