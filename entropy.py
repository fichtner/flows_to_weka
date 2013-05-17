import zlib
from math import log

# Caculate shannon entropy of a set of data
def shannon (data):
    # Whithin the for statement, we determine the frequency of each byte
    # in the dataset and if this frequency is not null we use it for the
    # entropy calculation

    if data == None or data == '':
    	data = ' '
    	
    data = list(bytearray(data))

    dataSize = len(data)

    ent = 0.0

    # a byte can take 256 values from 0 to 255. Here we are looping 256 times
    # to determine if each possible value of a byte is in the dataset
    for i in range(256):
        freq = float(data.count(i))/dataSize
        if freq > 0:    # to avoid an error for log(0)
            ent = ent + freq * log(freq, 2)

    return -ent

# Reasonable approximation to the Kolmogorov Complexity
# using the compression rate
# ref.: http://lorenzoriano.wordpress.com/tag/python/
def kolmogorov(data):
   if data == None or data == '':
   	return 0.0

   l = float(len(data))
   compr = zlib.compress(data)
   c = float(len(compr))/l
   if c > 1:
     return 1.0
   else:
     return c
