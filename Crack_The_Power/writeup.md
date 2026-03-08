# Crack the Power

## Category: 
Cryptography  

## Whats that

We are given an RSA-like cryptosystem with these parameters:

- **Modulus `n`**: A 4095 bit composite integer  
- **Public exponent `e`**: 20
- **Ciphertext `c`**: 3817 bit integer  

## What can we do

Standard RSA encryption computes: `c = m^(e)(mod n)`  
When `e` and `m` are small enough: `m < n^(1/e)`  
Modular reduction never triggers because: `m^(e) < n`

Sooooooooo:  
`c = m^(e) (over Z)`

## Exploitation

Since `c = m^(20)` over the integers, we can calculate `c`

### Method
`./src/attack.py`

## Flag

```
picoCTF{t1ny_e_381870dd}
```
