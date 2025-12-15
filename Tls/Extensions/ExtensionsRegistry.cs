using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Threading;
using NiL.Tools;

namespace NiL.Cryptography.Tls.Extensions;

public static class ExtensionsRegistry
{
    private static Dictionary<ExtensionType, Func<BigEndianStreamReader, ExtensionContext, ITlsExtension>> _extensions = new();

    private static volatile int _autoAttach = 0;

    public static bool AutoAttach
    {
        get => _autoAttach != 0;
        set
        {
            if (_autoAttach != 0 == value)
                return;

            var oldValue = Interlocked.CompareExchange(ref _autoAttach, value ? 1 : 0, value ? 0 : 1) != 0;

            if (oldValue == value)
                return;

            if (value)
            {
                AppDomain.CurrentDomain.AssemblyLoad += currentDomain_AssemblyLoad;
                var assemblies = AppDomain.CurrentDomain.GetAssemblies();

                lock (_extensions)
                {
                    for (var i = 0; i < assemblies.Length; i++)
                        findExtensions(assemblies[i]);
                }
            }
            else
            {
                AppDomain.CurrentDomain.AssemblyLoad -= currentDomain_AssemblyLoad;

                lock (_extensions)
                {
                    _extensions.Clear();
                    findExtensions(Assembly.GetExecutingAssembly());
                }
            }
        }
    }

    static ExtensionsRegistry()
    {
        lock (_extensions)
            findExtensions(Assembly.GetExecutingAssembly());
    }

    public static ITlsExtension ReadExtension(BigEndianStreamReader reader, ExtensionContext extensionContext)
    {
        var extensionType = (ExtensionType)reader.UInt16();
        if (!_extensions.TryGetValue(extensionType, out var extension))
            return UnknownTlsExtension.ReadFromReader(reader, extensionContext);

        return extension(reader, extensionContext);
    }

    private static void currentDomain_AssemblyLoad(object sender, AssemblyLoadEventArgs args)
    {
        lock (_extensions)
            findExtensions(args.LoadedAssembly);
    }

    private static void findExtensions(Assembly loadedAssembly)
    {
        var types = loadedAssembly.GetTypes();
        foreach (var type in types)
        {
            if (type != typeof(ITlsExtension) && typeof(ITlsExtension).IsAssignableFrom(type))
            {
                try
                {
                    addType(type);
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e);
                }
            }
        }
    }

    private static void addType(Type type)
    {
        var property = type.GetProperties().Where(x => x.Name == nameof(ITlsExtension.ExtensionType)).ToArray();

        if (property.Length == 0)
            return;

        if (property.Length > 1 || property.Any(x => !x.GetAccessors()[0].IsStatic))
            throw new InvalidOperationException(nameof(ITlsExtension.ExtensionType) + " not implemented properly for " + type.FullName);

        var extensionType = (ExtensionType)property[0].GetValue(null);

        if (extensionType == ExtensionType.Unknown && type != typeof(UnknownTlsExtension))
            throw new InvalidOperationException(nameof(ITlsExtension.ExtensionType) + " not implemented for " + type.FullName);

        if (type.GetInterfaces()
                .Where(x => x.IsGenericType && x.GetGenericTypeDefinition() == typeof(ITlsExtension<>))
                .Any(x => x.GetGenericArguments()[0] != type))
            throw new InvalidOperationException(nameof(ITlsExtension) + " not implemented properly for " + type.FullName);

        var methodInfo = type.GetMethod(nameof(ITlsExtension<UnknownTlsExtension>.ReadFromReader));

        if (methodInfo.ReturnType != type)
            throw new InvalidOperationException(nameof(ITlsExtension<UnknownTlsExtension>.ReadFromReader) + " not implemented for " + type.FullName);

        var method = Delegate.CreateDelegate(typeof(Func<BigEndianStreamReader, ExtensionContext, ITlsExtension>), methodInfo);

        _extensions.Add(extensionType, (Func<BigEndianStreamReader, ExtensionContext, ITlsExtension>)method);
    }
}
