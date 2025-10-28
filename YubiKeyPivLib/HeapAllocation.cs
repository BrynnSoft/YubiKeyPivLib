using System;
using System.Runtime.InteropServices;

namespace YubiKeyPivLib;

public class HeapAllocation : IDisposable
{
    public IntPtr Handle { get; }
    
    public HeapAllocation(int size)
    {
        Handle = Marshal.AllocHGlobal(size);
    }

    public void Dispose()
    {
        Marshal.FreeHGlobal(Handle);
        GC.SuppressFinalize(this);
    }
    
}