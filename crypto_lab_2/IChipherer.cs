using System;
using System.Collections.Generic;
using System.Text;

namespace crypto_lab_2
{
    interface IChipherer
    {
        byte[] Encrypt(byte[] plaintext);

        byte[] Decrypt(byte[] chiphertext);
    }
}
