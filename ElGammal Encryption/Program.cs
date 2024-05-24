using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;

namespace ElGammal_Encryption
{
    public static class Extensions
    {
        public static BigInteger NextBigInteger(this Random r, BigInteger min, BigInteger max)
        {
            BigInteger range = max - min;
            var ba = new byte[range.GetByteCount() + 1];
            r.NextBytes(ba);
            BigInteger result = new(ba);
            if (result.Sign == -1)
            {
                result *= -1;
            }
            result %= range;
            result += min;
            return result;
        }
        public static BigInteger ToPower(this BigInteger bas, BigInteger power)
        {
            BigInteger result = new(1);
            while (power > 0)
            {
                if (power % 2 == 0)
                {
                    bas *= bas;
                    power >>= 1;
                }
                else
                {
                    result *= bas;
                    power -= 1;
                }
            }
            return result;
        }
        public static BigInteger ToPowerModular(this BigInteger bas, BigInteger power, BigInteger Modulus)
        {
            BigInteger result = new(1);
            while (power > 0)
            {
                if (power % 2 == 0)
                {
                    bas = (bas * bas ) % Modulus;
                    power >>= 1;
                }
                else
                {
                    result = (result * bas) % Modulus;
                    power -= 1;
                }
            }
            return result;
        }
    }
    public class ElGammal(int key_size = 2048)
    {
        public static List<ulong> GeneratePrimes(int count)
        {
            List<ulong> primes = new(count);
            bool isPrime;
            for(ulong i = 2; primes.Count < count; i++)
            {
                isPrime = true;
                foreach(var p in primes)
                {
                    if((i % p) == 0)
                    {
                        isPrime = false;
                        break;
                    }
                }
                if (isPrime)
                {
                    primes.Add(i);
                }
            }
            return primes;
        }
        private readonly Random random = new();
        private readonly BigInteger bignum1 = ((BigInteger)2).ToPower(key_size - 1);
        private readonly BigInteger bignum2 = ((BigInteger)2).ToPower(2 * key_size - 1);
        private readonly List<ulong> primes = GeneratePrimes(2*key_size);
        public struct PublicKey
        {
            public BigInteger q, g, h;
        }
        public struct PrivateKey
        {
            public BigInteger k, q;
        }

        private static BigInteger GCD(BigInteger a, BigInteger b)
        {
            while (a != 0 && b != 0)
            {
                if (a > b)
                    a %= b;
                else
                    b %= a;
            }
            if (a.IsZero)
            {
                return b;
            }
            return a;
        }
        private async Task<BigInteger> CoPrime(BigInteger a)
        {
            await Task.CompletedTask;
            BigInteger coprime;
            do
            {
                coprime = random.NextBigInteger(bignum1, a);
            } while (GCD(coprime, a) != 1);
            return coprime;
        }
        private async Task<BigInteger> ModularPower(BigInteger bas , BigInteger power, BigInteger modulus)
        {
            await Task.CompletedTask;
            BigInteger result = new(1);
            bas %= modulus;
            while (power.Sign == 1)
            {
                var dividable = primes.AsParallel().Where(x => power % x == 0).ToArray();
                foreach (var div in dividable)
                {
                    bas = bas.ToPowerModular(div, modulus);
                    power /= div;
                }
                result = (result * bas) % modulus;
                power--;

            }
            return result % modulus;
        }

        public async Task<(PublicKey, PrivateKey)> GenerateKeysAsync()
        {
            PublicKey publicKey = new();
            PrivateKey privateKey = new();
            publicKey.q = random.NextBigInteger(bignum1, bignum2);
            publicKey.g = random.NextBigInteger(2, publicKey.q);
            privateKey.k = await CoPrime(publicKey.q);
            privateKey.q = publicKey.q;
            publicKey.h = await ModularPower(publicKey.g , privateKey.k, publicKey.q);
            return (publicKey, privateKey);
        }

        public async Task<(BigInteger shared_secret, BigInteger cipher)> ClientSide(PublicKey publicKey)
        {
            BigInteger k = await CoPrime(publicKey.q);
            var ss = await ModularPower(publicKey.h , k, publicKey.q);
            BigInteger ciph = await ModularPower(publicKey.g, k, publicKey.q);
            return (ss, ciph);
        }

        public async Task<BigInteger> ServerSide(PrivateKey privateKey, BigInteger cipher)
        {
            return await ModularPower(cipher, privateKey.k, privateKey.q);
        }
    }
    internal class Program
    {
        static void Main()
        {
            Console.Write("Trial times: ");
            ulong count = ulong.Parse(Console.ReadLine());
            Console.Write("Key size: ");
            int key = int.Parse(Console.ReadLine());
            TimeSpan total = TimeSpan.FromSeconds(0);
            Stopwatch sw = new();
            sw.Start();
            ElGammal elGammal = new(key);
            sw.Stop();
            Console.WriteLine($"calculation primes took {sw.Elapsed.TotalMilliseconds}ms");
            for (ulong i = 0; i < count; i++)
            {
                sw.Restart();
                var (public_key, private_key) = elGammal.GenerateKeysAsync().Result;
                var (client_shared_secret, cipher) = elGammal.ClientSide(public_key).Result;
                var server_shared_secret = elGammal.ServerSide(private_key, cipher).Result;
                Console.WriteLine(client_shared_secret == server_shared_secret);
                sw.Stop();
                total += sw.Elapsed;
                sw.Reset();
            }

            Console.WriteLine($"avarage handshake time for {key} bit key is {total.TotalMilliseconds / count}ms");
        }
    }
}
