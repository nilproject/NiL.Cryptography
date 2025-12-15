namespace NiL.Cryptography.Tls.Tls13;

public record HandshakeKeys(
    byte[] ClientHandshakeTrafficSecret,
    byte[] ServerHandshakeTrafficSecret,
    byte[] Derived);
