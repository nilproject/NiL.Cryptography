namespace NiL.Cryptography.Tls.Tls13;

public record TrafficKeyingMaterial(
    byte[] WriteKey,
    byte[] WriteIv);
