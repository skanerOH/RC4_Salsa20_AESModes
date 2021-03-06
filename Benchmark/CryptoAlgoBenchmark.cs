using BenchmarkDotNet.Attributes;
using crypto_lab_2;
using System;
using System.Collections.Generic;
using System.Text;

namespace Benchmark
{
    [SimpleJob(launchCount: 1, warmupCount: 0, targetCount: 1)]
    [MemoryDiagnoser]
    public class CryptoAlgoBenchmark
    {
        string rootpath = "C:\\Users\\Skaner\\Downloads\\";
        string inpFileName = "lect10-earley (2).ppt";
        private FileChipherer chipherer;

        //RC4
        [Benchmark]
        public void RC4Encrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.RC4);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void RC4Decrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.RC4);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }


        //Salsa20
        [Benchmark]
        public void Salsa20Encrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.Salsa20);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void Salsa20Decrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.Salsa20);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }


        //AES_ECB
        [Benchmark]
        public void AES_ECBEncrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_ECB);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void AES_ECBDecrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_ECB);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }



        //AES_CBC
        [Benchmark]
        public void AES_CBCEncrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CBC);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void AES_CBCDecrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CBC);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }


        //AES_CFB
        [Benchmark]
        public void AES_CFBEncrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CFB);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void AES_CFBDecrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CFB);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }


        //AES_OFB
        [Benchmark]
        public void AES_OFBEncrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_OFB);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void AES_OFBDecrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_OFB);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }


        //AES_CTR
        [Benchmark]
        public void AES_CTREncrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CTR);
            chipherer.Encrypt(rootpath + inpFileName, rootpath + "Encr_" + inpFileName);
        }

        [Benchmark]
        public void AES_CTRDecrypt()
        {
            chipherer = new FileChipherer(ChiphererAlgo.AES_CTR);
            chipherer.Decrypt(rootpath + "Encr_" + inpFileName, rootpath + "Decr_" + inpFileName);
        }
    }
}
