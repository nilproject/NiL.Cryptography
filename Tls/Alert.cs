using System.Runtime.InteropServices;

namespace NiL.Cryptography.Tls;

// https://tools.ietf.org/html/rfc5246#section-7.2
[StructLayout(LayoutKind.Sequential, Pack = 1, Size = 2)]
public struct Alert
{
    public AlertLevel Level;
    public AlertDescription Description;
}
