using System.Collections.Generic;
using System.Linq;

namespace NiL.Cryptography.Numerics;

public class Reducer
{
    public enum OpCode
    {
        Mul,
        Add,
        LoadValAndZero,
    }

    public struct Operation
    {
        public OpCode OpCode;
        public uint Arg;

        public override string ToString()
        {
            return OpCode + " " + Arg;
        }
    }

    public Operation[] Operations { get; }
    public int Length { get; }
    public int ModLength { get; }

    public Reducer(IEnumerable<Operation> operations, int length, int modLength)
    {
        Operations = operations.ToArray();
        Length = length;
        ModLength = modLength;
    }

    public unsafe void Reduce(uint* value)
    {
        var baseValue = 0ul;
        var activeValue = 0ul;

        var iters = Operations.Length;
        var modLen = ModLength;
        var len = Length;
        for (var i = 0; i < iters; i++)
        {
            ref var op = ref Operations[i];
            switch (op.OpCode)
            {
                case OpCode.Mul:
                    {
                        activeValue = baseValue * op.Arg;
                        break;
                    }

                case OpCode.LoadValAndZero:
                    {
                        activeValue = baseValue = value[op.Arg];
                        value[op.Arg] = 0;
                        break;
                    }

                case OpCode.Add:
                    {
                        var v = activeValue;
                        var j = op.Arg;
                        for (; v != 0; j++)
                        {
                            v += value[j];
                            value[j] = (uint)v;
                            v >>= 32;
                        }

                        break;
                    }
            }
        }
    }
}
