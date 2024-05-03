import hashlib
from bitarray import bitarray


class BloomFilter:

    def __init__(self, bits=293033333):
        # Password lists
        self.filter_set: set = set()
        self.checks_set: set = set()

        # Bloom filter
        self.bits = bits
        self.bloom_filter: bitarray = bitarray(bits)
        self.hashes: list = [hashlib.md5, hashlib.sha1, hashlib.sha256, hashlib.sha512]

        # Results
        self.true_positives = 0
        self.true_negatives = 0
        self.false_positives = 0
        self.false_negatives = 0
        self.total_trials = 0

    def start(self):
        # Load filter and checks lists with passwords
        self.load_filter_set()
        self.load_checks_set()

        # Create bloom filter
        self.create_bloom_filter()

        # Test dictionary passwords
        self.test_passwords()

        # Print results
        print(f"True Positives: {self.true_positives}")
        print(f"True Negatives: {self.true_negatives}")
        print(f"False Positives: {self.false_positives}")
        print(f"False Negatives: {self.false_negatives}")
        print(f"False Positives Percentage: {self.false_positives / self.total_trials * 100}%")

    def load_filter_set(self):
        """Loads filter list with bad passwords from rockyou"""
        with open("rockyou.ISO-8859-1.txt", 'r', encoding="ISO-8859-1") as f:
            for password in f:
                print(password)
                self.filter_set.add(password)

    def load_checks_set(self):
        """Loads checks list with passwords to be checked against the bloom filter"""
        with open("dictionary.txt", 'r', encoding="ISO-8859-1") as f:
            for password in f:
                print(password)
                self.checks_set.add(password)

    def create_bloom_filter(self):
        """Creates bloom filter using filter list and hashes"""
        # Loop through and hash passwords, setting bits in filter
        for password in self.filter_set:
            # Encode the password as bytes
            password_bytes = bytes(password, 'utf-8')
            # Hash the password with each func and set bf bits
            for hash_function in self.hashes:
                hash_object = hash_function(password_bytes)
                hash_value = int.from_bytes(hash_object.digest(), "big")
                index = hash_value % self.bits
                self.bloom_filter[index] = True

    def test_passwords(self):
        """Tests all passwords in checks list against bloom filter"""
        # Loop through passwords in checks list
        for password in self.checks_set:
            # Encode the password as bytes
            password_bytes = bytes(password, 'utf-8')
            # Boolean for positive/negative result
            positive: bool = True
            # Hash the password with each func and check result
            for hash_function in self.hashes:
                hash_object = hash_function(password_bytes)
                hash_value = int.from_bytes(hash_object.digest(), "big")
                index = hash_value % self.bits
                if not self.bloom_filter[index]:
                    positive = False
            # Set results according to true/false positive/negative
            password_in_filter: bool = password in self.filter_set
            if positive and password_in_filter:
                self.true_positives += 1
            elif positive and not password_in_filter:
                self.false_positives += 1
            elif not positive and password_in_filter:
                self.false_negatives += 1
            elif not positive and not password_in_filter:
                self.true_negatives += 1
            self.total_trials += 1


if __name__ == "__main__":
    bf = BloomFilter()
    bf.start()
