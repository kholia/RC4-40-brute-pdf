RC4-40-brute usage
==================

```
$ ./npdf2john samples/test.pdf
samples/test.pdf:$npdf$1*2*40*-4*1*16*c56bbc4145d25b468a873618cd71c2d3*32*bf38d7a59daaf38365a338e1fc07976102f1dfd6bdb52072032f57920109b43a*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499

$ ./RC4-40-brute 'samples/test.pdf:$npdf$1*2*40*-4*1*16*c56bbc4145d25b468a873618cd71c2d3*32*bf38d7a59daaf38365a338e1fc07976102f1dfd6bdb52072032f57920109b43a*32*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499'

```
