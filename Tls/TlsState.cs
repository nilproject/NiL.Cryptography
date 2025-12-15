namespace NiL.Cryptography.Tls;

public enum TlsState
{
    Initial = 0,
    ClientHelloGot,
    ServerHelloSent,
    ClientKeyExchangeGot,
    CipherSpecChangeGot,
    CertificateSent,
    ServerKeyExchangeSent,
    ServerHelloDoneSent,
    FinishedSent,
    Ready,
}
