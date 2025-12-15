namespace NiL.Cryptography.Tls.Extensions;

public enum ExtensionType : ushort
{
    ServerName = 0x0,

    SupportedGroups = 10,

    EcPointFormats = 11,

    SecureRemotePassword = 12,

    SignatureAlgorithms = 13,

    Heartbeat = 15,

    ApplicationLayerProtocolNegotiation = 16,

    Padding = 21,

    EncryptThenMac = 22,

    ExtendedMasterSecret = 23,

    PreSharedKey = 41,

    SupportedVersions = 43,

    PskKeyExchangeMode = 45,

    PostHandshakeAuth = 49,

    KeyShare = 51,

    Renegotiation = 0xff01,

    Unknown = 0xffff,
}
