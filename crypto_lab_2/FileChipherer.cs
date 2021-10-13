using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using crypto_lab_2.AES;
using crypto_lab_2.AES.ModeChipherers;

namespace crypto_lab_2
{
    public enum ChiphererAlgo
    {
        AESmodeECB,
        AESmodeCBC,
        AESmodeCFB,
        AESmodeOFB,
        AESmodeCTR,
        RC4,
        Salsa20
    }

    public class FileChipherer
    {
        static int BUFF_SIZE = 2048; //BUFF_SIZE % 64 = 0

        private readonly IChipherer chipherer;

        public FileChipherer(ChiphererAlgo algo, byte[] key)
        {
            switch (algo)
            {
                case ChiphererAlgo.AESmodeECB:
                    chipherer = new AESmodeECB(key);
                    break;
                case ChiphererAlgo.RC4:
                    chipherer = new RC4(key);
                    break;
                default:
                    return;
            }
        }

        public FileChipherer(ChiphererAlgo algo)
        {
            switch (algo)
            {
                case ChiphererAlgo.AESmodeECB:
                    chipherer = new AESmodeECB(Encoding.ASCII.GetBytes("aaaabbbbccccdddd"));
                    break;
                case ChiphererAlgo.AESmodeCBC:
                    chipherer = new AESmodeCBC(Encoding.ASCII.GetBytes("aaaabbbbccccdddd"), Encoding.ASCII.GetBytes("oooooooooooooooo"));
                    break;
                case ChiphererAlgo.AESmodeCFB:
                    chipherer = new AESmodeCFB(Encoding.ASCII.GetBytes("aaaabbbbccccdddd"), Encoding.ASCII.GetBytes("oooooooooooooooo"));
                    break;
                case ChiphererAlgo.AESmodeOFB:
                    chipherer = new AESmodeOFB(Encoding.ASCII.GetBytes("aaaabbbbccccdddd"), Encoding.ASCII.GetBytes("oooooooooooooooo"));
                    break;
                case ChiphererAlgo.AESmodeCTR:
                    chipherer = new AESmodeCTR(Encoding.ASCII.GetBytes("aaaabbbbccccdddd"), Encoding.ASCII.GetBytes("oooooooooooooooo"));
                    break;
                case ChiphererAlgo.RC4:
                    chipherer = new RC4(Encoding.ASCII.GetBytes("aaaaaaaabbbbbbbbccccccccdddddddd"));
                    break;
                case ChiphererAlgo.Salsa20:
                    chipherer = new Salsa20(Encoding.ASCII.GetBytes("aaaaaaaabbbbbbbbccccccccdddddddd"), new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
                    break;
                default:
                    return;
            }
        }

        public void Encrypt(string inputPath, string outputPath)
        {
            using (FileStream inputFile = File.OpenRead(inputPath))
            using (FileStream outputFile = File.Create(outputPath))
            {
                byte[] buff = new byte[BUFF_SIZE];
                while (inputFile.Read(buff, 0, buff.Length) > 0)
                {
                    outputFile.Write(chipherer.Encrypt(buff), 0, buff.Length);
                }
            }
        }

        public void Decrypt(string inputPath, string outputPath)
        {
            using (FileStream inputFile = File.OpenRead(inputPath))
            using (FileStream outputFile = File.Create(outputPath))
            {
                byte[] buff = new byte[BUFF_SIZE];
                while (inputFile.Read(buff, 0, buff.Length) > 0)
                {
                    outputFile.Write(chipherer.Decrypt(buff), 0, buff.Length);
                }
            }
        }
    }
}
