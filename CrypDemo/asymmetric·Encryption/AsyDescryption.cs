using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace CrypDemo.asymmetric_Encryption
{
	public class AsyDescryption
	{
		private static RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
		public static string _privateKey = rsa.ToXmlString(true);
		public static string _publicLey = rsa.ToXmlString(false);
		public static string EncryByRSACryptoServiceProvider(string input)
		{
			byte[] message = Encoding.Default.GetBytes(input);

			Console.WriteLine(rsa.KeySize);

			rsa.FromXmlString(_publicLey);

			byte[] outPut = rsa.Encrypt(message, false);

			return Convert.ToBase64String(outPut);
		}
		public static string DecryByRSACryptoServiceProvider(string input)
		{
			var data = Convert.FromBase64String(EncryByRSACryptoServiceProvider(input));
			rsa.FromXmlString(_privateKey);
			byte[] outPut = rsa.Decrypt(data, false);
			string result = Encoding.Default.GetString(outPut);

			return result;
		}
		public static string SignData(string input)
		{
			var data = Encoding.Default.GetBytes(input);
			rsa.FromXmlString(_privateKey);
			byte[] outPut = rsa.SignData(data, "SHA1");
			return Convert.ToBase64String(outPut);
		}
		public static bool VertifySignData(string input)
		{
			var data =Convert.FromBase64String( SignData(input));
			rsa.FromXmlString(_publicLey);
			bool result = rsa.VerifyData(Encoding.Default.GetBytes(input), "SHA1", data);
			return result;
		}
		public static string SignDataUseCertify(string input)
		{
			byte[] message = Encoding.UTF8.GetBytes(input);
			string path = @"D:\Ceetificate\1.p12";
			X509Certificate2 x509 = new X509Certificate2(path);
			SHA1 sha1 = new SHA1CryptoServiceProvider();
			byte[] hashByte = sha1.ComputeHash(message);
			RSAPKCS1SignatureFormatter sign = new RSAPKCS1SignatureFormatter();
			sign.SetKey(x509.PrivateKey);
			sign.SetHashAlgorithm("SHA1");
			byte[] result = sign.CreateSignature(hashByte);
			return Convert.ToBase64String(result);
		}
		public static bool VertifySignedByCertify(string input)
		{
			var data = Convert.FromBase64String(SignDataUseCertify(input));
			string path = @"D:\Ceetificate\1.p12";
			X509Certificate2 x509 = new X509Certificate2(path);
			RSAPKCS1SignatureFormatter sign = new RSAPKCS1SignatureFormatter();
			rsa.FromXmlString(x509.PublicKey.Key.ToXmlString(false));
			bool vertify = rsa.VerifyData(Encoding.Default.GetBytes(input), "SHA1", data);
			return vertify;
		}
		public static void Vertify()
		{
			byte[] hash;
			using (SHA256 sha256 = SHA256.Create())
			{
				byte[] data = new byte[] { 59, 4, 248, 102, 77, 97, 142, 201, 210, 12, 224, 93, 25, 41, 100, 197, 213, 134, 130, 135 };
				hash = sha256.ComputeHash(data);
			}
			//Create an RSASignatureFormatter object and pass it the 
			//RSACryptoServiceProvider to transfer the key information.
			RSAPKCS1SignatureFormatter RSAFormatter = new RSAPKCS1SignatureFormatter(rsa);
			//Set the hash algorithm to SHA256.
			RSAFormatter.SetHashAlgorithm("SHA256");
			//Create a signature for HashValue and return it.
			byte[] signedHash = RSAFormatter.CreateSignature(hash);
			//Create an RSAPKCS1SignatureDeformatter object and pass it the  
			//RSACryptoServiceProvider to transfer the key information.
			RSAPKCS1SignatureDeformatter RSADeformatter = new RSAPKCS1SignatureDeformatter(rsa);
			RSADeformatter.SetHashAlgorithm("SHA256");
			//Verify the hash and display the results to the console. 
			if (RSADeformatter.VerifySignature(hash, signedHash))
			{
				Console.WriteLine("The signature was verified.");
			}
			else
			{
				Console.WriteLine("The signature was not verified.");
			}
		}
	}
}
