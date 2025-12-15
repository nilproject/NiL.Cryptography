using System;

namespace NiL.Cryptography.Tls;

public enum CurveType : byte
{
    [Obsolete("rfc8422")]
    ExplicitPrime = 1,
    [Obsolete("rfc8422")]
    Explicit_char2 = 2,

    NamedCurve = 3,
}
