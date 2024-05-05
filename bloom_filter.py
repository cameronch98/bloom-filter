import hashlib
from bitarray import bitarray
from sortedcontainers import SortedSet


class BloomFilter:

    def __init__(self, bits=293033333):
        # Password lists
        self.filter_set: SortedSet = SortedSet()
        self.checks_set: SortedSet = SortedSet()

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
        print("Loading test password and filter password sets ...")
        self.load_filter_set()
        self.load_checks_set()
        print("Password sets loaded\n")

        # Create bloom filter
        print("Loading bloom filter using filter password set ...")
        self.create_bloom_filter()
        print("Bloom filter created\n")

        # Test dictionary passwords
        print("Testing passwords with bloom filter ...")
        self.test_passwords()
        print("Testing complete\n")

        # Print results
        print(f"{'True Positives':18} -> {self.true_positives:8}")
        print(f"{'True Negatives':18} -> {self.true_negatives:8}")
        print(f"{'False Positives':18} -> {self.false_positives:8}")
        print(f"{'False Negatives':18} -> {self.false_negatives:8}")
        print(
            f"{'False Positives %':18} -> {self.false_positives / self.total_trials * 100:8.2f}"
        )

    def load_filter_set(self):
        """Loads filter list with bad passwords from rockyou"""
        with open("rockyou.ISO-8859-1.txt", "r", encoding="ISO-8859-1") as f:
            for password in f:
                self.filter_set.add(password)

    def load_checks_set(self):
        """Loads checks list with passwords to be checked against the bloom filter"""
        with open("dictionary.txt", "r", encoding="ISO-8859-1") as f:
            for password in f:
                self.checks_set.add(password)

    def create_bloom_filter(self):
        """Creates bloom filter using filter list and hashes"""
        # Loop through and hash passwords, setting bits in filter
        for password in self.filter_set:
            # Encode the password as bytes
            password_bytes = bytes(password, "utf-8")
            # Hash the password with each func and set bf bits
            for hash_function in self.hashes:
                hash_object = hash_function(password_bytes)
                hash_value = int.from_bytes(hash_object.digest(), "big")
                index = hash_value % self.bits
                self.bloom_filter[index] = True

    def interpret_result(self, positive: bool, in_filter: bool) -> str:
        """Updates results based on if positive/negative and if password in filter set"""
        # Update results accordingly
        self.total_trials += 1
        if positive and in_filter:
            self.true_positives += 1
            return "True Positive"
        elif positive and not in_filter:
            self.false_positives += 1
            return "False Positive"
        elif not positive and in_filter:
            self.false_negatives += 1
            return "False Negative"
        else:
            self.true_negatives += 1
            return "True Negative"

    def test_passwords(self):
        """Tests all passwords in checks list against bloom filter"""
        # Loop through passwords in checks list
        for password in self.checks_set:
            # Encode the password as bytes
            password_bytes: bytes = bytes(password, "utf-8")
            # Boolean for presence of password in filter set
            in_filter: bool = password in self.filter_set
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
            result = self.interpret_result(positive, in_filter)
            print(f"Password '{password.strip()}' -> {result}")


if __name__ == "__main__":
    bf = BloomFilter()
    bf.start()
