using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
namespace OpenSSL
{
    class Program
    {
        static void Main(string[] args)
        {
            Process process = new Process();
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;
            process.StartInfo.FileName = @"C:\Program Files\Git\usr\bin\openssl.exe";

            GenerateKeys(process, "ca"); //Gerar o conjunto de chave pública/privada de uma Autoridade Certificadora
            GenerateKeys(process, "bob"); //Gerar o conjunto de chave pública/privada de Bob;
            SignBobPublicKey(process); //Assinar a chave pública de Bob usando a SK da CA

            if (!VerifyBobAuthenticity()) //Alice de posse da PK da CA, verifica se o certificado de Bob esta correto
            {
                Console.WriteLine("Bob is not Bob!");
                return;
            }
            
            GenerateKeys(process, "alice"); //Alice gera uma chave segura(usando o openssl) e 
            EncryptSessionKey(process); // cifra ela usando a PK de Bob

            File.Move(@"alice\private_encrypted.enc", @"bob\private_encrypted.enc"); //Alice e “envia” para o Bob;
            File.Move(@"alice\keyfile.enc", @"bob\keyfile.enc"); //Alice e “envia” para o Bob;

            CreateMessage(process); //Alice cifra um segredo usando a chave de sessão 
            File.Move(@"alice\message.enc", @"bob\message.enc"); //e envia para Bob

            DecryptSessionKey(process); // Bob decifra a chave de sessão enviada por Alice
            DecryptMessage(process); //Bob decifra o segredo

            Console.ReadKey();
        }
        public static void GenerateKeys(Process process, string name)
        {
            if (!Directory.Exists(name))
            {
                Directory.CreateDirectory(name);
            }
            
            process.StartInfo.Arguments = $@"genrsa -out {name}\{name}_private.pem 2048"; // generate key
            process.Start();
            process.WaitForExit();

            process.StartInfo.Arguments = $@"rsa -pubout -in {name}\{name}_private.pem -out {name}_public.pem"; //extract public key
            process.Start();
            process.WaitForExit();
        }

        public static void SignBobPublicKey(Process process)
        {
            process.StartInfo.Arguments = $@"dgst -sha256 -sign ca\ca_private.pem -out bob_signed_key bob_public.pem"; // sign bob's public key 
            process.Start();
            process.WaitForExit();
        }

        public static bool VerifyBobAuthenticity()
        {
            string line = string.Empty;
            var proc = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = @"C:\Program Files\Git\usr\bin\openssl.exe",
                    Arguments = $@"dgst -sha256 -verify ca_public.pem -signature bob_signed_key bob_public.pem", // verify bob's public key 
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                }
            };
            proc.Start();
            while (!proc.StandardOutput.EndOfStream)
                line = proc.StandardOutput.ReadLine();

            return (line == "Verified OK");
        }

        public static void EncryptSessionKey(Process process)
        {
            process.StartInfo.Arguments = $@"rand -out alice\keyfile -hex 20";
            process.Start();
            process.WaitForExit();
            
            process.StartInfo.Arguments = $@"enc -aes-256-cbc -pbkdf2 -salt -in alice\alice_private.pem -out alice\private_encrypted.enc -pass file:alice\keyfile";
            process.Start();
            process.WaitForExit();
            
            process.StartInfo.Arguments = $@"rsautl -encrypt -pubin -inkey bob_public.pem -in alice\keyfile -out alice\keyfile.enc";
            process.Start();
            process.WaitForExit();
        }

        public static void CreateMessage(Process process)
        {
            string path = @"alice\message.txt";
            if (!File.Exists(path))
                using (StreamWriter sw = File.CreateText(path)) //create a message
                    sw.WriteLine("Hello Bob, how are you?");

            process.StartInfo.Arguments = $@"rsautl -encrypt -in alice\message.txt -pubin -inkey alice_public.pem -out alice\message.enc";
            process.Start();
            process.WaitForExit();
            File.Delete(path);
        }

        public static void DecryptSessionKey(Process process)
        {
            process.StartInfo.Arguments = $@"rsautl  -decrypt -in bob\keyfile.enc -inkey bob\bob_private.pem -out bob\keyfile.key";
            process.Start();
            process.WaitForExit();
            
            process.StartInfo.Arguments = $@"enc -aes-256-cbc -pbkdf2 -d -salt -in bob\private_encrypted.enc -out bob\session.pem -pass file:bob\keyfile.key";
            process.Start();
            process.WaitForExit();

            File.Delete(@"bob\private_encrypted.enc");
            File.Delete(@"bob\keyfile.enc");
        }

        public static void DecryptMessage(Process process)
        {
            process.StartInfo.Arguments = $@"rsautl -decrypt -in bob\message.enc -inkey bob\session.pem -out bob\message.txt";
            process.Start();
            process.WaitForExit();
            File.Delete(@"bob\message.enc");

            Console.WriteLine(File.ReadAllText(@"bob\message.txt"));
        }
    }
}