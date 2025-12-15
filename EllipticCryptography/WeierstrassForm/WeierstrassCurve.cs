using System;
using System.Collections.Generic;
using System.Linq.Expressions;
using System.Runtime.InteropServices;
using NiL.Cryptography.Numerics;

namespace NiL.Cryptography.EllipticCryptography.WeierstrassForm;

public unsafe delegate void ReduceFunc(uint* value);

public sealed class WeierstrassCurve<TSize> : ICurve where TSize : INumberSize
{
    private static readonly int _intsCount = TSize.Size / 32;

    public WeierstrassCurve(BigUInt<TSize> p, BigUInt<TSize> a, BigUInt<TSize> b)
    {
        P = p;
        A = a;
        B = b;

        if (a + 3 == p)
            AIsMinus3 = true;
        else if (a == 0)
            AIsZero = true;

        InversedModData = NumericsBase.ComputeInversedModData(p.GetRawBuffer());

        var alignedModLen = Array.FindLastIndex(InversedModData.AlignedMod, x => x != 0) + 1;
        var reduceData = computeReduceData(alignedModLen);
        //ReduceData = reduceData;

        //var reducer = buildReducer(alignedModLen, reduceData);

        //Reducer = reducer;

        //ReduceFunc = buildReduceFunc(reducer);
        //ReduceFunc = default;

        //test(reducer);
    }

    private unsafe ReduceFunc buildReduceFunc(Reducer reducer)
    {
        var readFunc = new Func<nint, int, int>(Marshal.ReadInt32).Method;
        var writeFunc = new Action<nint, int, int>(Marshal.WriteInt32).Method;

        var four = Expression.Constant(4);

        var lines = new List<Expression>();
        var valuePrm = Expression.Parameter(typeof(nint), "value");
        var activeValuePrm = Expression.Parameter(typeof(ulong), "activeValue");
        var baseValuePrm = Expression.Parameter(typeof(ulong), "baseValue");
        var vPrm = Expression.Parameter(typeof(ulong), "v");
        var jPrm = Expression.Parameter(typeof(int), "j");
        var lenConst = Expression.Constant(_intsCount);

        Expression read(Expression index)
        {
            if (index.Type != typeof(int))
                index = Expression.Convert(index, typeof(int));

            return Expression.Call(
                readFunc,
                [
                    valuePrm,
                    Expression.Multiply(index, four)
                ]);
        }

        Expression write(Expression index, Expression value)
        {
            if (index.Type != typeof(int))
                index = Expression.Convert(index, typeof(int));

            return Expression.Call(
                writeFunc,
                new Expression[]
                {
                    valuePrm,
                    Expression.Multiply(index, four),
                    value
                });
        }

        for (var i = 0; i < reducer.Operations.Length; i++)
        {
            ref var op = ref reducer.Operations[i];
            switch (op.OpCode)
            {
                case Reducer.OpCode.Mul:
                {
                    lines.Add(
                        Expression.Assign(activeValuePrm,
                            Expression.Multiply(baseValuePrm,
                                Expression.Convert(Expression.Constant(op.Arg), typeof(ulong)))));
                    break;
                }

                case Reducer.OpCode.LoadValAndZero:
                {
                    var cRead = Expression.Convert(read(Expression.Constant(op.Arg)), typeof(ulong));
                    lines.Add(
                        Expression.Assign(
                            activeValuePrm,
                            Expression.Assign(
                                baseValuePrm,
                                cRead)));
                    lines.Add(write(Expression.Constant(op.Arg), Expression.Constant(0)));
                    break;
                }

                case Reducer.OpCode.Add:
                {
                    var label = Expression.Label();
                    lines.Add(Expression.Assign(vPrm, activeValuePrm));
                    lines.Add(Expression.Assign(jPrm, Expression.Convert(Expression.Constant(op.Arg), typeof(int))));
                    lines.Add(
                        Expression.Loop(
                            Expression.Block(
                                Expression.IfThen(
                                    Expression.Not(
                                        Expression.AndAlso(
                                            Expression.LessThan(jPrm, lenConst),
                                            Expression.NotEqual(vPrm, Expression.Constant(0ul)))),
                                    Expression.Break(label)),

                                Expression.AddAssign(vPrm, Expression.Convert(read(jPrm), typeof(ulong))),
                                write(jPrm, Expression.Convert(vPrm, typeof(int))),
                                Expression.RightShiftAssign(vPrm, Expression.Constant(32)),

                                Expression.Increment(jPrm)),
                            label));

                    break;
                }
            }
        }

        var result = Expression.Lambda<Action<nint>>(
            Expression.Block(
                new[]
                {
                    activeValuePrm,
                    baseValuePrm,
                    vPrm,
                    jPrm
                },
                lines.ToArray()),
            valuePrm);

        var r = result.Compile(false);
        return x => r((nint)x);
    }

    private unsafe void test(Reducer reducer)
    {
        var tempValue = stackalloc uint[_intsCount];
        tempValue[8] = 1;
        tempValue[9] = 1;
        tempValue[10] = 1;
        tempValue[11] = 1;
        tempValue[12] = 1;
        tempValue[13] = 1;
        tempValue[14] = 1;
        tempValue[15] = 1;

        var tempValue2 = stackalloc uint[_intsCount];
        for (var i = 0; i < _intsCount; i++)
            tempValue2[i] = tempValue[i];

        var tempValue3 = stackalloc uint[_intsCount];
        for (var i = 0; i < _intsCount; i++)
            tempValue3[i] = tempValue[i];

        reducer.Reduce(tempValue);
        NumericsBase.Reduce(tempValue2, _intsCount, InversedModData);

        var sums = new List<string>();
        var baseValue = string.Empty;
        var activeValue = string.Empty;
        var prevIndex = 0u;
        for (var i = 0; i < reducer.Operations.Length; i++)
        {
            ref var op = ref reducer.Operations[i];
            switch (op.OpCode)
            {
                case Reducer.OpCode.Mul:
                {
                    activeValue = baseValue + "x" + op.Arg.ToString("x1");
                    sums.Add("var " + activeValue + " = " + baseValue + " * " + op.Arg + "ul");
                    break;
                }

                case Reducer.OpCode.LoadValAndZero:
                {
                    if (op.Arg < prevIndex)
                    {
                        i = int.MaxValue - 1;
                        break;
                    }

                    prevIndex = op.Arg;

                    baseValue = "x" + op.Arg;
                    sums.Add("var " + baseValue + " = x[" + op.Arg + "]");
                    activeValue = baseValue;
                    break;
                }

                case Reducer.OpCode.Add:
                {
                    var j = op.Arg;

                    sums.Add("x[" + j + "] += " + activeValue);

                    break;
                }
            }
        }

        sums.Sort();

        var reduceCode = string.Join(";" + Environment.NewLine, sums) + ";";
    }

    private unsafe uint[][] computeReduceData(int alignedModLen)
    {
        var reduceData = new uint[_intsCount - alignedModLen][];
        for (var i = 0; i < reduceData.Length; i++)
        {
            reduceData[i] = new uint[_intsCount];
            fixed (uint* value = reduceData[i])
            {
                reduceData[i][i + alignedModLen] = 1;
                NumericsBase.Reduce(value, _intsCount, InversedModData);
            }
        }

        //var debugData = reduceData
        //    .Select(x => string.Concat(x.Select(y => y.ToString("x2"))))
        //    .ToArray();

        //var debugData = string.Concat(reduceData[7].Select(y => y.ToString("x2")));

        return reduceData;
    }

    private unsafe Reducer buildReducer(int alignedModLen, uint[][] reduceData)
    {
        var operations = new List<Reducer.Operation>();
        var processed = stackalloc bool[_intsCount];
        var limit = _intsCount - alignedModLen;
        for (var i = 0; i < reduceData.Length + 4; i++)
        {
            var rdIndex = i < limit ? i : i % limit % 2;

            for (var j = 0; j < reduceData[rdIndex].Length; j++)
            {
                processed[j] = false;
            }

            operations.Add(new Reducer.Operation
            {
                OpCode = Reducer.OpCode.LoadValAndZero,
                Arg = (uint)(alignedModLen + rdIndex),
            });

            var oneProcessed = false;
            for (var c = 0; c < 2; c++)
            {
                for (var j = 0; j < reduceData[rdIndex].Length; j++)
                {
                    if (processed[j])
                        continue;

                    var value = reduceData[rdIndex][j];

                    if (value == 0)
                        continue;

                    if (value != 1)
                    {
                        if (!oneProcessed)
                            continue;

                        operations.Add(new Reducer.Operation
                        {
                            OpCode = Reducer.OpCode.Mul,
                            Arg = value,
                        });
                    }
                    else
                    {
                        oneProcessed = true;
                    }

                    for (var k = 0; k < reduceData[rdIndex].Length; k++)
                    {
                        if (reduceData[rdIndex][k] == value)
                        {
                            processed[k] = true;

                            operations.Add(new Reducer.Operation
                            {
                                OpCode = Reducer.OpCode.Add,
                                Arg = (uint)k,
                            });
                        }
                    }
                }

                oneProcessed = true;
            }
        }

        return new Reducer(operations.ToArray(), _intsCount, alignedModLen);
    }

    public WeierstrassCurvePoint<TSize> CreatePoint(BigUInt<TSize> x, BigUInt<TSize> y)
    {
        var z = new BigUInt<TSize>(1);
        var ys = y * y % P;
        var zs = z * z % P;
        var zt = zs * z % P;
        var xt = x * x % P * x % P;
        var axzs = A * x % P * zs % P;
        var r = (xt + axzs + B * zt % P) % P;
        r %= P;
        var l = ys * zt % P;

        if (l != r)
            throw new InvalidOperationException();

        return new WeierstrassCurvePoint<TSize>(x, y, this);
    }

    ICurvePoint ICurve.CreatePoint(IBigUInt xCoord, IBigUInt yCoord)
    {
        var x = (BigUInt<TSize>)xCoord;
        var y = (BigUInt<TSize>)yCoord;

        return CreatePoint(x, y);
    }

    public ICurvePoint CreatePoint(IBigUInt x) => throw new NotSupportedException();

    public readonly BigUInt<TSize> P;
    public readonly BigUInt<TSize> A;
    public readonly BigUInt<TSize> B;

    IBigUInt ICurve.P => P;
    IBigUInt ICurve.A => A;
    IBigUInt ICurve.B => B;

    public readonly bool AIsMinus3;
    public readonly bool AIsZero;

    //internal readonly uint[][] ReduceData;
    public InversedModData InversedModData { get; }

    public bool IsPrecomputeSupported => true;
    //public readonly Reducer Reducer;
    //public ReduceFunc ReduceFunc;
}
