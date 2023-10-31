using System.Security.Cryptography;
using System.Text;
using KiemTra_30_10.Helpers;

namespace KiemTra_30_10
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.InputEncoding = Console.OutputEncoding = Encoding.Unicode;
            string key = GenerateKeyForAll();
            Console.Write("Chuỗi cần mã hóa: ");
            string input = Console.ReadLine() ?? "";
            string aesEncrypt = CipherHelper.Encrypt<Aes>(input, key);
            string rc2Encrypt = CipherHelper.Encrypt<RC2>(input, key);
            string rijndaelEncrypt = CipherHelper.Encrypt<Rijndael>(input, key);
            string desEncrypt = CipherHelper.Encrypt<DES>(input, key);
            string tripleDesEncrypt = CipherHelper.Encrypt<TripleDES>(input, key);



            Console.WriteLine($"Mã hóa theo aes: {aesEncrypt}");
            Console.WriteLine($"Mã hóa theo RC2: {rc2Encrypt}");
            Console.WriteLine($"Mã hóa theo Rijndael: {rijndaelEncrypt}");// giống aes
            Console.WriteLine($"Mã hóa theo DES: {desEncrypt}");
            Console.WriteLine($"Mã hóa theo TripleDES: {tripleDesEncrypt}");

            string aesDecrypt = CipherHelper.Decrypt<Aes>(aesEncrypt, key);
            string rc2Decrypt = CipherHelper.Decrypt<RC2>(rc2Encrypt, key);
            string rijndaelDecrypt = CipherHelper.Decrypt<Rijndael>(rijndaelEncrypt, key);
            string desDecrypt = CipherHelper.Decrypt<DES>(desEncrypt, key);
            string tripleDesDecrypt = CipherHelper.Decrypt<TripleDES>(tripleDesEncrypt, key);

            Console.WriteLine("".PadLeft(50,'*'));

            Console.WriteLine($"Giải mã theo aes: {aesDecrypt}");
            Console.WriteLine($"Giải mã theo RC2: {rc2Decrypt}");
            Console.WriteLine($"Giải mã theo Rijndael: {rijndaelDecrypt}");// giống aes
            Console.WriteLine($"Giải mã theo DES: {desDecrypt}");
            Console.WriteLine($"Giải mã theo TripleDES: {tripleDesDecrypt}");



            Console.ReadLine();
        }


        public static string GenerateKeyForAll()
        {

            var tripleDes = new TripleDESCryptoServiceProvider();

            tripleDes.GenerateKey();

            byte[] key = tripleDes.Key;

            return Encoding.ASCII.GetString(key);

        }
    }
}