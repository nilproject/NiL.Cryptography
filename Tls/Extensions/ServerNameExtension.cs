using System.Text;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public enum ServerNameType : byte
{
    HostName = 0,
}

public record struct ServerName(ServerNameType Type, string Name);

public sealed class ServerNameExtension : ITlsExtension<ServerNameExtension>
{
    public ServerNameExtension(ServerName[] serverNames)
    {
        ServerNames = serverNames;
    }

    public static ExtensionType ExtensionType => ExtensionType.ServerName;

    public ServerName[] ServerNames { get; }

    public static ServerNameExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        var listSize = reader.UInt16();
        var names = new ServerName[listSize];
        for (int i = 0; i < listSize;)
        {
            var nameType = reader.UInt8();
            var nameLen = reader.UInt16();
            names[i] = new((ServerNameType)nameType, Encoding.ASCII.GetString(reader.Bytes(nameLen)));
            i += 1 + 2 + nameLen;
        }

        return new ServerNameExtension(names);
    }
}
