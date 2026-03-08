```bash
python3 -c "import hashlib;h=open('level3.hash.bin','rb').read();f=open('level3.flag.txt.enc','rb').read();p=[x for x in['6997','3ac8','f0ac','4b17','ec27','4e66','865e']if hashlib.md5(x.encode()).digest()==h][0];print(''.join(chr(o^ord(c))for o,c in zip(f,p*100)))"
```