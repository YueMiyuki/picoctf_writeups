# DISKO 2

## Category
Forensics

## Difficulty
Medium

## Description
Disk forensics challenge. Find the flag in a raw disk image.

## What we have
Got a compressed disk image `disko-2.dd.gz`:
- Gzipped raw dump
- Multiple partitions
- Linux ext4 filesystem

## How?
**Check the image**
```bash
fdisk disko-2.dd
```
```
Disk: disko-2.dd        geometry: 812/4/63 [204800 sectors]
Signature: 0xAA55
         Starting       Ending
 #: id  cyl  hd sec -  cyl  hd sec [     start -       size]
------------------------------------------------------------------------
 1: 83    0  32  33 -    3  80  13 [      2048 -      51200] Linux files*
 2: 0B    3  80  14 -    7 100  29 [     53248 -      65536] Win95 FAT-32
 3: 00    0   0   0 -    0   0   0 [         0 -          0] unused      
 4: 00    0   0   0 -    0   0   0 [         0 -          0] unused   
 ```

Found:
- Linux partition starts at sector 2048

**Extract the linux**
```bash
dd if=/tmp/disko-2.dd of=/tmp/linux-partition.dd bs=512 skip=2048 count=51200
```
```
51200+0 records in
51200+0 records out
26214400 bytes transferred in 0.088410 secs (296509445 bytes/sec)   
```

**Find the flag**
```bash
strings /tmp/linux-partition.dd | grep "picoCTF"
```
```
picoCTF{4_P4Rt_1t_i5_055dd175} 
```

## Flag
```
picoCTF{4_P4Rt_1t_i5_055dd175}
```