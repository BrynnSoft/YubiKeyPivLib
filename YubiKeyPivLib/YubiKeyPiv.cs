using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace YubiKeyPivLib
{
    public class YubiKeyPiv : IDisposable
    {
        private readonly IntPtr _state;
        
        public YubiKeyPiv(bool verbose = false)
        {
            _state = Marshal.AllocHGlobal(3000);
            var result = YubiKeyPivNative.ykpiv_init(ref _state, (verbose ? 1 : 0));
            if (result != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                Marshal.FreeHGlobal(_state);
            }
        }

        public void Dispose()
        {
            YubiKeyPivNative.ykpiv_done(_state);
            Marshal.FreeHGlobal(_state);
        }

        public string GetLibraryVersion()
        {
            return YubiKeyPivNative.ykpiv_check_version("2.0.0")!;
        }

        public void Connect(string wanted)
        {
            YubiKeyPivNative.ykpiv_connect(_state, wanted);
        }

        public IEnumerable<string> GetReaders()
        {
            var len = 256;
            var readers = new char[len];
            var rc = YubiKeyPivNative.ykpiv_list_readers(_state, readers, ref len);
            var str = new string(readers).TrimEnd('\0');
            return str.Split('\0');
        }

        public void Disconnect()
        {
            YubiKeyPivNative.ykpiv_disconnect(_state);
        }

        public string GetVersion()
        {
            var len = 32;
            var version = new char[len];
            var rc = YubiKeyPivNative.ykpiv_get_version(_state, version, len);
            var str = new string(version);
            return str;
        }

        public uint GetSerial()
        {
            uint serial = 0;
            YubiKeyPivNative.ykpiv_get_serial(_state, ref serial);
            return serial;
        }

        public IList<SlotCertificate> GetKeys()
        {
            byte keyCount = 0;
            var data = new IntPtr();
            uint dataSize = 2048;
            var rc = YubiKeyPivNative.ykpiv_util_list_keys(_state, ref keyCount, ref data, ref dataSize);
            var keysData = new byte[dataSize];
            Marshal.Copy(data, keysData, 0, (int)dataSize);
            YubiKeyPivNative.ykpiv_util_free(_state, data);
            var reader = new BinaryReader(new MemoryStream(keysData));
            var slotCerts = new List<SlotCertificate>();
            for (var keyIndex = 0; keyIndex < keyCount; keyIndex++)
            {
                var slot = reader.ReadByte();
                var certLength = reader.ReadUInt16();
                var certBytes = reader.ReadBytes(certLength);
                var cert = X509CertificateLoader.LoadCertificate(certBytes);
                slotCerts.Add(new SlotCertificate()
                {
                    Slot = (YubiKeySlot)slot,
                    Certificate = cert,
                });
            }
            return slotCerts;
        }

        public PublicKey GenerateNewKeyInSlot(YubiKeySlot slot, YubiKeyAlgorithm algorithm, YubiKeyPinPolicy pinPolicy,
            YubiKeyTouchPolicy touchPolicy)
        {
            var mod = IntPtr.Zero;
            uint modSize = 0;
            var exp = IntPtr.Zero;
            uint expSize = 0;
            var point = IntPtr.Zero;
            uint pointSize = 0;
            
            var rc = YubiKeyPivNative.ykpiv_util_generate_key(_state, (byte)slot, (byte)algorithm, (byte)pinPolicy, (byte)touchPolicy, ref mod, ref modSize, ref exp, ref expSize, ref point, ref pointSize);

            if (rc != YubiKeyPivNative.ykpiv_rc.YKPIV_OK)
            {
                
            }

            switch (algorithm)
            {
                case YubiKeyAlgorithm.RSA_1024:
                case YubiKeyAlgorithm.RSA_2048:
                case YubiKeyAlgorithm.RSA_3072:
                case YubiKeyAlgorithm.RSA_4096:
                {
                    var rsaParams = new RSAParameters();
                    var modBytes = new byte[modSize];
                    Marshal.Copy(mod, modBytes, 0, (int)modSize);
                    YubiKeyPivNative.ykpiv_util_free(_state, mod);
                    var expBytes = new byte[expSize];
                    Marshal.Copy(exp, expBytes, 0, (int)expSize);
                    YubiKeyPivNative.ykpiv_util_free(_state, exp);
                    rsaParams.Modulus = modBytes;
                    rsaParams.Exponent = expBytes;
                    var rsa = RSA.Create();
                    rsa.ImportParameters(rsaParams);
                    return new PublicKey(rsa);
                }
                case YubiKeyAlgorithm.ECCP_256:
                case YubiKeyAlgorithm.ECCP_384:
                case YubiKeyAlgorithm.ED_25519:
                    YubiKeyPivNative.ykpiv_util_free(_state, point);
                    throw new NotImplementedException();
                case YubiKeyAlgorithm.Auto:
                default:
                    throw new NotImplementedException();
            }
        }
    }
}