using NiL.Cryptography.EllipticCryptography;

namespace NiL.Cryptography.Tls;

public interface IEllipticCurveProvider
{
    public CurveDefinition CurveDefinition { get; }
}
