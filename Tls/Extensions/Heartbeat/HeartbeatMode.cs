namespace NiL.Cryptography.Tls.Extensions.Heartbeat;

public enum HeartbeatMode : byte
{
    PeerAllowedToSend = 1,

    PeerNotAllowedToSend = 2,
}