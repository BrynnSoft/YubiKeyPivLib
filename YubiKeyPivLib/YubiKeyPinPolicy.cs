namespace YubiKeyPivLib;

public enum YubiKeyPinPolicy : byte
{
    Default = 0,
    Never = 1,
    Once = 2,
    Always = 3,
    MatchOnce = 4,
    MatchAlways = 5
}