using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public sealed class PostHandshakeAuthExtension : ITlsExtension<PostHandshakeAuthExtension>
{
    public static ExtensionType ExtensionType => ExtensionType.PostHandshakeAuth;

    public static PostHandshakeAuthExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        return new PostHandshakeAuthExtension();
    }
}
