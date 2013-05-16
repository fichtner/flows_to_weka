import zlib

# Reasonable approximation to the Kolmogorov Complexity
# using the compression rate
# ref.: http://lorenzoriano.wordpress.com/tag/python/
def kolmogorov(data):
   l = float(len(data))
   if l == 0:
	   return 0
   compr = zlib.compress(data)
   c = float(len(compr))
   return c/l
