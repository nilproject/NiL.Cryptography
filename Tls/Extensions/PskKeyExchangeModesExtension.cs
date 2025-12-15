using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public enum PskKeyExchangeMode : byte
{
    PskOnlyKeyEstablishment = 0,
    PskWith_Ec_DheKeyEstablishment = 1,
}

public sealed class PskKeyExchangeModesExtension : ITlsExtension<PskKeyExchangeModesExtension>
{
    public PskKeyExchangeModesExtension(PskKeyExchangeMode[] modes)
    {
        Modes = modes;
    }

    public static ExtensionType ExtensionType => ExtensionType.PskKeyExchangeMode;

    public PskKeyExchangeMode[] Modes { get; }

    public static PskKeyExchangeModesExtension ReadFromReader(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        _ = reader.UInt16();
        var count = reader.UInt8();
        var modes = new PskKeyExchangeMode[count];
        for (var i = 0; i < count; i++)
        {
            modes[i] = (PskKeyExchangeMode)reader.UInt8();
        }

        return new PskKeyExchangeModesExtension(modes);
    }
}
