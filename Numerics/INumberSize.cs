namespace NiL.Cryptography.Numerics;

public interface INumberSize
{
    static abstract int Size { get; }
}
public abstract class B128 : INumberSize
{
    public static int Size => 128;
}

public abstract class B256 : INumberSize
{
    public static int Size => 256;
}

public abstract class B512 : INumberSize
{
    public static int Size => 512;
}
