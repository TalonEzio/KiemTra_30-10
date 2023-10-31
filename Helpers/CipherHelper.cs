using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KiemTra_30_10.Helpers
{
    public class CipherHelper
    {
        public static string Encrypt<T>(string data, string key, string initVector = "abcede0123456789")
        where T : SymmetricAlgorithm

        {
            string algorithmName = typeof(T).Name;

            using (var algorithm = SymmetricAlgorithm.Create(algorithmName) as T)
            {
                var ivLength = algorithm.BlockSize / 8;
                byte[] initializationVector = Encoding.ASCII.GetBytes(initVector, 0, ivLength);

                //Console.WriteLine($"Key size: {algorithm.KeySize}, Block size: {algorithm.BlockSize}, Feedback size: {algorithm.FeedbackSize}");

                int keyLength = 16;
                if (algorithm is DES)
                    keyLength = 8;
                if (algorithm is TripleDES)
                    keyLength = 24;
                var keyByte = Encoding.UTF8.GetBytes(key, 0, keyLength);


                algorithm.Key = keyByte;
                algorithm.IV = initializationVector;
                var symmetricEncryptor = algorithm.CreateEncryptor(algorithm.Key, algorithm.IV);
                using (var memoryStream = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(memoryStream as Stream,
                               symmetricEncryptor, CryptoStreamMode.Write))
                    {
                        using (var streamWriter = new StreamWriter(cryptoStream as Stream))
                        {
                            streamWriter.Write(data);
                        }
                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }
        public static string Decrypt<T>(string cipherText, string key, string initVector = "abcede0123456789")
            where T : SymmetricAlgorithm
        {

            string algorithmName = typeof(T).Name;

            byte[] buffer = Convert.FromBase64String(cipherText);
            using (T algorithm = SymmetricAlgorithm.Create(algorithmName) as T)
            {
                var ivLength = algorithm.BlockSize / 8;
                byte[] initializationVector = Encoding.ASCII.GetBytes(initVector, 0, ivLength);

                //Console.WriteLine($"Key size: {algorithm.KeySize}, Block size: {algorithm.BlockSize}, Feedback size: {algorithm.FeedbackSize}");

                int keyLength = 16;
                if (algorithm is DES)
                    keyLength = 8;
                if (algorithm is TripleDES)
                    keyLength = 24;
                var keyByte = Encoding.UTF8.GetBytes(key, 0, keyLength);


                algorithm.Key = keyByte;
                algorithm.IV = initializationVector;
                var decryptor = algorithm.CreateDecryptor(algorithm.Key, algorithm.IV);
                using (var memoryStream = new MemoryStream(buffer))
                {
                    using (var cryptoStream = new CryptoStream(memoryStream as Stream,
                               decryptor, CryptoStreamMode.Read))
                    {
                        using (var streamReader = new StreamReader(cryptoStream as Stream))
                        {
                            return streamReader.ReadToEnd();
                        }
                    }
                }
            }
        }
    }
}
