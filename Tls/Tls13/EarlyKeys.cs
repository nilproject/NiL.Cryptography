namespace NiL.Cryptography.Tls.Tls13;


public record EarlyKeys(
    byte[] BinderKey,
    byte[] ClientEarlyTrafficSecret,
    byte[] EarlyExporterMasterSecret,
    byte[] Derived);
