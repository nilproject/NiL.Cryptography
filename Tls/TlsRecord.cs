using System;

namespace NiL.Cryptography.Tls;

internal struct TlsRecord
{
    public TlsContentType TlsContentType;
    public TlsVersion TlsVersion;
    public ArraySegment<byte>[] Data;
}
