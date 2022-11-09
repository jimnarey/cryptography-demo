import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from lib import demo

# tc = unittest.TestCase()

class TestIsPrime(unittest.TestCase):

    def test_tiny_primes(self):
        for num in (2, 3, 5):
            self.assertTrue(demo.is_prime(num))

    def test_zero(self):
        self.assertFalse(demo.is_prime(0))

    def test_one(self):
        self.assertFalse(demo.is_prime(1))

    def test_small_non_prime(self):
        self.assertFalse(demo.is_prime(20))

    @patch('lib.demo.rabin_miller')
    def test_calls_rabin_miller_for_large_prime(self, mock_rabin_miller):
        demo.is_prime(1039)
        mock_rabin_miller.assert_called_once_with(1039)


class TestRabinMiller(unittest.TestCase):

    def test_large_primes(self):
        for num in (7873, 7151, 5923, 2477, 1609):
            self.assertTrue(demo.rabin_miller(num))

    # def test_non_primes(self):
    #     for num in (373646,):
    #         print(num)
    #         self.assertFalse(demo.rabin_miller(num))


class TestGetGCD(unittest.TestCase):

    def test_get_gcds(self):
        self.assertEqual(demo.euclid(47564,7589329), 11)
        self.assertEqual(demo.euclid(847589,93846), 1)
        self.assertEqual(demo.euclid(462,586), 2)



#
# System Tests. There are better tools for this but unittest is
# built in
#

class TestRSAEncryptionDecryptionLoop(unittest.TestCase):

    def setUp(self):
        key_size = 8
        self.p = demo.generate_prime(key_size)
        self.q = demo.generate_prime(key_size, exclude=self.p)
        self.n = self.p * self.q
        self.pn = (self.p - 1) * (self.q -1)
        self.keys = demo.get_potential_public_key_parts(self.pn)
        self.e, self.d, tried_keys = demo.find_valid_key_pair(self.keys, self.pn)

    def test_encryption_with_d_decrption_with_e(self):
        for i in range(0, 255):
            s = demo.rsa(i, self.d, self.n)
            u = demo.rsa(s, self.e, self.n)
            self.assertEqual(i, u)

    def test_encryption_with_e_decrption_with_d(self):
        for i in range(0, 255):
            s = demo.rsa(i, self.e, self.n)
            u = demo.rsa(s, self.d, self.n)
            self.assertEqual(i, u)


if __name__ == '__main__':
    unittest.main()
