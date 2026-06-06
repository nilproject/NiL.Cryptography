using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace NiL.Cryptography.Tls;

public sealed class TlsStream : Stream
{
    private int _bufferPos;
    private bool _closed;
    private readonly Queue<byte[]> _inputApplicationDataBuffers;
    private readonly TlsSession _session;
    private readonly MemoryStream _outgoingBuffer;

    public TimeSpan ReceiveTimeout { get; set; } = TimeSpan.FromSeconds(5);

    internal TlsStream(TlsSession session)
    {
        _session = session ?? throw new ArgumentNullException(nameof(session));
        _inputApplicationDataBuffers = new Queue<byte[]>();
        _outgoingBuffer = new MemoryStream();
    }

    protected override void Dispose(bool disposing)
    {
        if (_closed)
            return;

        lock (_outgoingBuffer)
        {
            if (_closed)
                return;

            _closed = true;

            Flush();

            _outgoingBuffer.Dispose();
            _inputApplicationDataBuffers.Clear();

            base.Dispose(disposing);
        }
    }

    internal void EnqueueApplicationData(byte[] buffer)
    {
        lock (_inputApplicationDataBuffers)
        {
            _inputApplicationDataBuffers.Enqueue(buffer);
        }
    }

    public int Available
    {
        get
        {
            if (_inputApplicationDataBuffers.Count < 1)
                _session.Pump(1);

            lock (_inputApplicationDataBuffers)
            {
                return _inputApplicationDataBuffers.Sum(x => x.Length) - _bufferPos;
            }
        }
    }

    public override bool CanRead => true;

    public override bool CanSeek => false;

    public override bool CanWrite => true;

    public override long Length => throw new NotSupportedException();

    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override void Flush()
    {
        if (_outgoingBuffer.Length == 0)
            return;

        lock (_outgoingBuffer)
        {
            if (_outgoingBuffer.Length == 0)
                return;

            _session.SendApplicationData(new ArraySegment<byte>(_outgoingBuffer.GetBuffer(), 0, (int)_outgoingBuffer.Length));
            _outgoingBuffer.SetLength(0);
        }
    }

    public override int Read(byte[] buffer, int offset, int count)
    {
        if (buffer == null)
            throw new NullReferenceException();

        if (count + offset > buffer.Length)
            throw new ArgumentOutOfRangeException();

        var start = Environment.TickCount64;
        var i = 0;
        while (i < count)
        {
            do
            {
                _session.Pump(1, _inputApplicationDataBuffers.Count == 0 && i == 0);
            }
            while (_inputApplicationDataBuffers.Count == 0
                    && i == 0
                    && Environment.TickCount64 - start < ReceiveTimeout.TotalMilliseconds);

            if (_inputApplicationDataBuffers.Count == 0 && i == 0)
            {
                return 0;
            }

            lock (_inputApplicationDataBuffers)
            {
                if (_inputApplicationDataBuffers.Count == 0)
                    break;

                var sourceBuffer = _inputApplicationDataBuffers.Peek();

                for (; i < count && _bufferPos < sourceBuffer.Length; i++)
                    buffer[offset++] = sourceBuffer[_bufferPos++];

                if (_bufferPos == sourceBuffer.Length)
                {
                    _inputApplicationDataBuffers.Dequeue();
                    _bufferPos = 0;
                }
            }
        }

        return i;
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        lock (_outgoingBuffer)
        {
            _outgoingBuffer.Write(buffer);

            //if (_outgoingBuffer.Length > 65535)
            {
                Flush();
            }
        }
    }

    public override void Write(byte[] buffer, int offset, int count)
        => Write(new ReadOnlySpan<byte>(buffer, offset, count));
}
