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