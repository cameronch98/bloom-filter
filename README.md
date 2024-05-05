# Bloom Filter

An instructive program that creates a 293,033,333 bit bloom filter using the md5, sha1, sha256, sha512 hash functions. The list of bad passwords used to create the bloom filter is included in rockyou.ISO-8859-1.txt and the passwords to be tested against the bloom filter are included in dictionary.txt.

### MacOS/Linux

First, clone the repository or download/extract the files. Then, it is recommended to go to the project directory and create a virtual environment as follows: 

```
python<version> -m venv <name-for-venv>
```

Then, we need to activate the venv by running:

```
source <name-for-venv>/bin/activate
```

Now that the virtual environment is enabled in the terminal, we need to install the packages required by the program that reside in requirements.txt. For reference, the packages that need to be installed are bitarray and sortedcontainers. To do so, we can run the following command:

```
pip install -r requirements.txt
```

To run the bloom filter experiment, we can enter one of the following:

```
python bloom_filter.py
```
```
python3 bloom_filter.py
```
```
<name-for-venv>/bin/python bloom_filter.py
```

# Usage
Once the program begin, the passwords will be loaded into their respective SortedSets and then the bloom filter will be created. Once that has completed, the passwords from dictionary.txt will begin being tested against the bloom filter. The results of each password will be printed to the terminal, signifying if that particular password resulted in a true positive, true negative, false positive, or false negative result. Finally, the final statistics will be shown, including the total number of each type of result as well as the percentage of false positives. 
