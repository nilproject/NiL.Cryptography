namespace NiL.Cryptography.Tls.Extensions;

/*public abstract class PreSharedKeyExtension : ITlsExtension<PreSharedKeyExtension>
{
    public sealed class ClientPreSharedKeyExtension : PreSharedKeyExtension
    {
        public OfferedPsks OfferedPsks { get; init; }
    }

    public sealed class ServerPreSharedKeyExtension : PreSharedKeyExtension
    {
        public ushort SelectedIdentity { get; init; }
    }

    public class PskIdentity
    {
        public byte[] Identity { get; init; }
        public uint ObfuscatedTicketAge { get; init; }
    }

    public class OfferedPsks
    {
        public PskIdentity Identities { get; init; }
        public byte[][] Binders { get; init; }
    }

    public PreSharedKeyExtension()
    {
    }

    public static ExtensionType ExtensionType => ExtensionType.PreSharedKey;

    public PskKeyExchangeMode[] Modes { get; }

    public static PreSharedKeyExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();

        if (extensionContext is ExtensionContext.ClientHello)
        {
            
        }
    }
}*/