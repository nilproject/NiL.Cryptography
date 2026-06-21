using NiL.Cryptography.Tls.KeyExchange;

namespace NiL.Cryptography.Tls;

public interface IPreMasterKeyDerivationAlgorithm
{
    int KeyLength { get; }
    KeyExchangeAlgorithm Id { get; }

    #region TLS 1.3
    EphemeralKeysSet DeriveEphemeralKeys(KeyExchangeParams keyExchangeParams);
    #endregion

    #region TLS 1.2
    byte[] DerivePreMasterKey(byte[] otherSidePublic, byte[] privateKey);
    #endregion
}
