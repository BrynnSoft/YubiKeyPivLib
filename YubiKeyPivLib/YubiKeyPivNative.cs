using System;
using System.Runtime.InteropServices;
using System.Text;

namespace YubiKeyPivLib
{
    internal class YubiKeyPivNative
    {
        internal enum ykpiv_rc : int
        {
            YKPIV_OK = 0,
            YKPIV_MEMORY_ERROR = -1,
            YKPIV_PCSC_ERROR = -2,
            YKPIV_SIZE_ERROR = -3,
            YKPIV_APPLET_ERROR = -4,
            YKPIV_AUTHENTICATION_ERROR = -5,
            YKPIV_RANDOMNESS_ERROR = -6,
            YKPIV_GENERIC_ERROR = -7,
            YKPIV_KEY_ERROR = -8,
            YKPIV_PARSE_ERROR = -9,
            YKPIV_WRONG_PIN = -10,
            YKPIV_INVALID_OBJECT = -11,
            YKPIV_ALGORITHM_ERROR = -12,
            YKPIV_PIN_LOCKED = -13,
            YKPIV_ARGUMENT_ERROR = -14, //i.e. invalid input argument
            YKPIV_RANGE_ERROR = -15, //i.e. value range error
            YKPIV_NOT_SUPPORTED = -16,
            YKPIV_PCSC_SERVICE_ERROR = -17,
        }
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_init(ref IntPtr state, int verbose);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_done(IntPtr state);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string ykpiv_check_version(string version);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern string ykpiv_check_version(IntPtr version);
        
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern ykpiv_rc ykpiv_connect(IntPtr state, string wanted);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        internal static extern ykpiv_rc ykpiv_list_readers(IntPtr state, [Out] char[] readers, ref int length);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_disconnect(IntPtr state);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_get_version(IntPtr state, [Out] char[] version, int length);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_get_serial(IntPtr state, ref uint serial);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_attest(IntPtr state, byte key, byte[] data, int dataSize);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_free(IntPtr state, IntPtr data);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_list_keys(IntPtr state, ref byte keyCount, ref IntPtr data, ref uint dataLength);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_read_cert(IntPtr state, byte slot, ref IntPtr data, ref uint dataLength);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_write_cert(IntPtr state, byte slot, byte[] data, uint dataLength, byte certInfo);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_delete_cert(IntPtr state, byte slot);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_generate_key(IntPtr state, byte slot, byte algorithm, byte pinPolicy, byte touchPolicy, ref IntPtr modulus, ref uint modulusLength, ref IntPtr exponent, ref uint exponentLength, ref IntPtr point, ref uint pointLength);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_verify(IntPtr state, string? pin, ref int tries);

        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_get_pin_retries(IntPtr state, ref int tries);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_global_reset(IntPtr state);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_reset(IntPtr state);
        
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_get_cccid(IntPtr state, IntPtr ccid);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_set_cccid(IntPtr state, IntPtr ccid);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_get_cardid(IntPtr state, IntPtr cardid);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_set_cardid(IntPtr state, IntPtr cardid);

        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_authenticate2(IntPtr state, byte[]? key, int keyLength);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_util_get_protected_mgm(IntPtr state, IntPtr mgm);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_set_mgmkey(IntPtr state, byte[] mgm);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_change_pin(IntPtr state, string currentPin, int currentPinLength, string newPin, int newPinLength, ref int tries);
        
        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_change_puk(IntPtr state, string currentPuk, int currentPukLength, string newPuk, int newPukLength, ref int tries);

        [DllImport("ykpiv", CallingConvention = CallingConvention.Cdecl)]
        internal static extern ykpiv_rc ykpiv_unblock_pin(IntPtr state, string puk, int pukLength, string newPin, int newPinLength, ref int tries);

    }
}