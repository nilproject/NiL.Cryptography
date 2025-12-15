//#define BENCH

namespace NiL.Cryptography.Numerics;

public struct InversedModData
{
    public uint[] AlignedMod;
    public int InvModLen;
    public int ModLen;
    public uint[] InvMod;
    public bool Is256k1;
    public bool Is256r1;
}
