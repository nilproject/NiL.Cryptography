using System;
using System.Security.Cryptography;

namespace NiL.Cryptography.Encryption;

public sealed class RC4
{
    /// <summary>
    /// Состояние шифрования
    /// </summary>
    private byte[] _s = new byte[256];

    /// <summary>
    /// Переменные состояния шифрования
    /// </summary>
    private int _a = 0, _b = 0;

    /// <summary>
    /// Устанавливает новый ключ шифрования, предварительно сбрасывая состояние
    /// </summary>
    public void SetKey(byte[] key)
    {
        if (key == null)
            throw new ArgumentNullException("key");

        _a = 0;
        _b = 0;
        for (int i = 0; i < _s.Length; i++)
            _s[i] = (byte)i;

        var j = 0;
        for (int i = 0; i < _s.Length; i++)
        {
            j = (j + _s[i] + key[i % key.Length]) % 256;
            var t = _s[i];
            _s[i] = _s[j];
            _s[j] = t;
        }
    }

    /// <summary>
    /// Создаёт представитель класса ARC4 со случайным ключом длинной 256 байт
    /// </summary>
    public RC4()
    {
        using var generator = RandomNumberGenerator.Create();
        var k = new byte[256];
        generator.GetBytes(k);
        SetKey(k);
    }

    /// <summary>
    /// Создаёт представитель класса ARC4 с заданным ключом
    /// </summary>
    /// <param name="key">Ключ шифрования</param>
    public RC4(byte[] key)
    {
        if (key.Length != 256)
            throw new ArgumentException();

        SetKey(key);
    }

    /// <summary>
    /// Шифрование заголовка сообщения указанной длины
    /// </summary>
    /// <param name="data">Массив байт, представляющих сообщение</param>
    public void Crypt(byte[] data)
    {
        if (data == null)
            throw new ArgumentNullException("data");

        for (int i = 0; i < data.Length; i++)
        {
            _a++;
            _a %= 256;
            _b += _s[_a];
            _b %= 256;

            var t = _s[_a];
            _s[_a] = _s[_b];
            _s[_b] = t;

            var xor = _s[_a] + _s[_b];
            xor %= 256;
            data[i] ^= _s[xor];
        }
    }

    /// <summary>
    /// Пропуск заданного количества байт в потоке шифрования
    /// </summary>
    /// <param name="length">Количество пропускаеммых байтов</param>
    public void Drop(int length)
    {
        for (int i = 0; i < length; i++)
        {
            _a++;
            _a %= _s.Length;
            _b += _s[_a];
            _b %= _s.Length;

            var t = _s[_a];
            _s[_a] = _s[_b];
            _s[_b] = t;
        }
    }
}
