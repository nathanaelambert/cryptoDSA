Your tasks are to compute Sigi and P Wi for i = 1, 2, as shown in Figure 1 where Sigi serves as
Transaction i (=T xi) and P Wi is the Proof-of-Work (PW) for Transaction i. In this project,
we omit the competing processing in the Bitcoin blockchain (i.e., you are the only miner in
the system). Also each block only contains one transaction. Your tasks are specified as follows
with a total 20 marks.
(a) (4 marks) Check that the system parameters p, q and g satisfy the three criteria in Table
1. You need to provide the factorization of p − 1, and explain your verification process.
Explain why we only pick sk1 as a number less than 224 bits. Compute pki, i = 1, 2, 3.
(b) (6 marks) Sign and validate transactions by DSA: implement a DSA module which enables
@G. Gong, ECE 409, Cryptography and Sys. Security, Winter 2024 5
the user can sign the transactions and a miner can verify the signed transaction. (Note
that since we set all inputs being zero, so mi = T xi, i = 1, 2, 3.)
(1) User 1: sign his transaction: Sigsk1 (m1) = (r1, s1), i.e., compute the signature over
m1, k1, r1 = (gk1 mod p) mod q, k−1
1 mod q and s1 = k−1
1 (h(m1) + xr) mod q.
(2) A miner: verify Sigsk1 (m1), i.e., compute the values of u, v, w and verify whether
w = r.
(3) User 2: sign his transaction m2 = T x2 using the key pair (sk2, pk2), i.e., executing
the same steps as User 1.
(c) (6 marks) Proof-of-Work (PW): Implement a module for a miner to compute a PW where
SHA3-224 is used as a hash function h in P W1 and P W2 computations.
(1) Find pre-images of h such that
P W1 = h(h(amt0)||m1||nonce1) = 00 · · · 0︸ ︷︷ ︸
k
∗ ∗ · · · ∗︸ ︷︷ ︸
224−k
P W2 = h(h(m1)||m2||nonce2) = 00 · · · 0︸ ︷︷ ︸
k
∗ ∗ · · · ∗︸ ︷︷ ︸
224−k
where ∗ means any value and noncei, i = 1, 2 are any 128-bit numbers. Here you
request to use k ≥ 24 until you cannot do this exhaustive search (e.g., your program
runs more than 10 hours without output), then you record the timing for the value
of k which you are successfully to get a preimage. You should vary a nonce in order
to obtain a k-consecutive leading zeros of SHA3-224 hash value. Your results on
hash values P W1 and P W2 should be represented as hexadecimal numbers. You are
requested to use Python or SageMath for this project. (You may use open source
programs in c/c++ to verify your results.)
(2) Determine the average number of trials which you need to get one PW in (1) and
provide the number of the actual trials in order to get your solution.
(d) (4 marks) Security analysis:
(a) Discuss why PW can prevent double spending in the Bitcoin blockchain network.
(b) Provide analysis why the public-keys in Bitcoin do not need certificates.
(e) (Optional) If you do this correctly, you will get two bonus mark. In the above DSA, if
SHA-224 is replaced by LFSR with period 2112 − 1. It works in the following way: an
initial state is loaded as GPS time when the user starts the program of DSA and it runs
224 clock cycles without output, then a 224-bit pseudorandom number will be a binary
number given by the concatenation of the 224th state and 225th state. Show a possible
attack that Attacker can steal a victim’s Bitcoin with a sound probability.

## First draft :

Proof of Work : for each transaction : 

hash chain of length 3 (1 block = 1 transaction)
The 3 transactions :
1. 
amt_0 = 5 BTC → 0x05
amt_1 = 4 BTC → 0x04
amt_2 = 3 BTC → 0x03

### implement DSA 112-bit security
1. checkparameters : A1, A2, A3



### user :

### miner : 
compute sig i and pw i

python DSA library for testing

sha3-224 

## 4 
# 4.A
The 3 criterie are :
- A1. p: a prime number lying between 1024 and 2048 bits
- A2. q: a 224-bit prime factor of p − 1
- A3. g: an element g ∈ Fp with order q

At first I thought about writing my own code for these tests, like : 
```py
def is_prime(num):
    for i in range(2, ceil(sqrt(num))):
        if num % i == 0:
            return False
    return True
```
But python was not happy about it : `OverflowError: int too large to convert to float`

So I decided to use the library: `pycryptodome`. In particular the [util.number](https://pythonhosted.org/pycrypto/Crypto.Util.number-module.html) module provides useful functions like `size`, `isPrime`

as well as the `pow` function from the standard python library

source code :   

```py
from Crypto.Util import number as n

p= ...
q= ...
g= ...

print(f"n.size(p)    : {n.size(p)} bits.")
print(f"n.isPrime(p) : {n.isPrime(p)}")
print(f"n.size(q)    : {n.size(q)} bits.")
print(f"(p-1) % q    : {(p-1) % q}")
print(f"n.isPrime(q) : {n.isPrime(q)}")
print(f"pow(g, q, p) : {pow(g, q, p)}")
```
result :   

```py
n.size(p)    : 2048 bits.
n.isPrime(p) : True
n.size(q)    : 224 bits.
(p-1) % q    : 0
n.isPrime(q) : True
pow(g, q, p) : 1
```

p,q and g verify the 3 criteria.

Here is the code used to compute the prime factorization of p-1:

```py
from Crypto.Util import number as n
def factorise(num, prime_factors, next_factor):
    if n.isPrime(num):
        prime_factors.append(num)
        return prime_factors

    if next_factor != 1:
        prime_factors.append(next_factor)
        return factorise(num // next_factor, prime_factors, 1)
    
    # order of magnitude of square root
    approx_sqrt_num = pow(2, n.size(num) // 2)
    # run 3 iterations of Newtons method for approximation square root
    for i in range(3):
        approx_sqrt_num = (approx_sqrt_num**2 + num) // 2*approx_sqrt_num

    # find next factor
    for i in range(2, approx_sqrt_num + 1):
        if num % i == 0:
            return factorise(num, prime_factors, i)
    
    # error : num is not prime but has no factor
    return [-1]
```

and to verify the factorization : 
```py
from Crypto.Util import number as n
from functools import reduce
import operator

def check_factorization(factors, product):
    for f in factors:
        if not n.isPrime(f):
            print(f"factor {f} is not prime")
            return False
    
    return reduce(operator.mul, factors, 1) == product
```

which gave:
```py
factorisation of p-1 : 
[13479974306915323548855049186344013292925286365246579443817723220231, 2, 599352188457547639693740171522680835865322184075286620256386716439921029334782998562008313995103840817116953210359643511447372101221464995653177706653918911634015555633001801773590292023083604552613918655194669929368962688659673544061885990566694774938089095597940505443430714573194211134223784784744939911387314440899638056016474270609853063142638329500429039904897328933858412897374253962878313102199163400319655392723027703101354927814377851954345336880097584669598515815463134218486896858352351187255794957262790967727451704317515673833695348341]
```


TODO :
Explain why we only pick sk1 as a number less than 224 bits. Compute pki, i = 1, 2, 3.