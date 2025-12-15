using System;

namespace NiL.Cryptography.Tls.Extensions.Renegotiation;

public struct RenegotiationInfo
{
    public readonly byte[] Info;

    public RenegotiationInfo(byte[] bytes)
    {
        if (bytes.Length < 0 || bytes.Length > 255)
            throw new ArgumentOutOfRangeException();

        Info = bytes;
    }
}
