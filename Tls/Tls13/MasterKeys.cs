namespace NiL.Cryptography.Tls.Tls13;

public record MasterKeys(
    byte[] ClientApplicationTrafficSecret0,
    byte[] ServerApplicationTrafficSecret0,
    byte[] ExporterMasterSecret,
    byte[] ResumptionMasterSecret);
