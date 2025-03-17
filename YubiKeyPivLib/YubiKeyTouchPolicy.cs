namespace YubiKeyPivLib;

public enum YubiKeyTouchPolicy : byte
{
    Default = 0,
    Never = 1,
    Always = 2,
    Cached = 3,
    
    Auto = 255
}