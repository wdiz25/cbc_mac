# Assignment 4: Forging Basic CBC-MAC
### Author: William Disman

## 1. Basic CBC-MAC

### 1a.
$\mathsf{Gen}$ samples $k \leftarrow \{0,1\}^{128}$ uniformly at random.

$\mathsf{Mac}_k(m)$ takes message $m$ and key $k$. For each block of the message, where $m = m_1 \,\|\, \cdots \,\|\, m_\ell$, $m_i$ is XORed with the chain value $x_{i-1}$. Pseudorandom function $F_k$ accepts this value and outputs $x_i$. For the first block of the message $m_1$, $x_0 = 0^{128}$. The resulting tag is $t = x_\ell = F_k(m_\ell \oplus x_{\ell - 1})$.

$$
x_0 = 0^{128}, \qquad x_i = F_k(m_i \oplus x_{i-1}) \quad (1 \leq i \leq \ell), \qquad t = x_\ell
$$

$\mathsf{Vrfy}_k(m, t)$ computes $\hat{t} = \mathsf{Mac}_k(m)$ and outputs $1$ if $\hat{t} = t$ otherwise $0$. This comparison occurs in constant time.

### 1b.
CBC-MAC and CBC-mode encryption are different in two major ways. First, CBC-MAC uses the same IV ($x_0 = 0^{128}$) for all computations. With CBC-mode encryption, a different IV should be chosen each time. If CBC-MAC didn't use the same IV each time, an attacker could manipulate the value of $x_0$ and $m_1$, yet the message would still pass verification. If the same value is XORed into both $m_1$ and $x_0$, the resulting $x_1$ would not change. Additionally, CBC-MAC only outputs one value $t$. When using CBC-mode encryption a ciphertext $c_i$ is output for each block. If the intermediate values were revealed, an attacker who queries $m_1 \,\|\, m_2$ would learn $x_1 = F_k(m_1) = \mathsf{Mac}_k(m_1)$, giving a valid forgery $(m_1, x_1)$ on a message that was never queried.

### 1c.

Basic CBC-MAC is only secure for fixed length messages. For a fixed $\ell$, every message authenticated with the same key $k$ must consist of exactly $\ell$ blocks, where $\ell$ must be fixed in advance. If messages with a different number of blocks are allowed using the same key, CBC-MAC is forgeable.

## 2. A Forgery on Messages of Different Lengths

### 2a.

The first $\ell$ blocks of $m^*$ are  $m_1, \ldots, m_\ell$, and $x^*_0 = 0^{128} = x_0$. This means that the chain matches that of $m$:
$$
x^*_i = x_i \quad (0 \leq i \leq \ell), \qquad \text{so } x^*_\ell = x_\ell = t 
$$

Block $\ell+1$  is $m'_1 \oplus t$. Following the same pattern established in 1a:
$$
x^*_{\ell+1} = F_k((m'_1 \oplus t) \oplus x^*_\ell) = F_k((m'_1 \oplus t) \oplus t) = F_k(m'_1)
$$

This equals $x'_1 = F_k(m'_1 \oplus x'_0) = F_k(m'_1 \oplus 0^{128}) = F_k(m'_1)$.

For $j = 2, \ldots, \ell'$, block $\ell + j$ of $m^*$ is $m'_j$. Since the value of $x^*_{\ell+1}$ is the same as $x'_1$, the chain values that follow are the same as for $m'$.
$$
x^*_{\ell+j} = F_k(m'_j \oplus x^*_{\ell+j-1}) = F_k(m'_j \oplus x'_{j-1}) = x'_j \quad (2 \leq j \leq \ell')
$$

Thus, the resulting tag does not rely on the values of $m$ in $m^*$:
$$
\mathsf{Mac}_k(m^*) = x^*_{\ell+\ell'} = x'_{\ell'} = t'
$$
If $\ell' = 1$, the chain ends at block $\ell + 1$, and the same conclusion holds.

Since $m^*$ has $\ell^* = \ell + \ell'$ blocks, $\ell + \ell' \gt \ell$ since $\ell' \geq 1$ and $\ell + \ell' \gt \ell'$ since $\ell \geq 1$. Thus, messages with different lengths cannot be the same message and $(m^*, t')$ is a valid forgery.

### 2b.

#### Query 1:
Query $m = M_1$, which has $\ell = 1$ block and receive its tag $t_1$.

#### Choosing Query 2:

By 2a, the forged message is
$$
m^* = m_1 \,\|\, (m'_1 \oplus t_1) \,\|\, m'_2 \,\|\, \cdots \,\|\, m'_{\ell'}.
$$
For $m^* = M$:

- Block 1: $m_1 = M_1$ (from Query 1)
- Block 2: $m'_1 \oplus t_1 = M_2$, so $m'_1 = M_2 \oplus t_1$
- Blocks 3+: $m'_j = M_{j+1}$ for $j = 2, \ldots,L-1$

So $\ell' = L - 1$.

#### Query 2:
Query $m' = (M_2 \oplus t_1) \,\|\, M_3 \,\|\, \cdots \,\|\, M_L$ and receive its tag $t'$. (If $L = 2$, then $m' = M_2 \oplus t_1$, a single block.)

#### Forgery:
Output $(M, t')$. By 2a, $\mathsf{Mac}_k(M) = \mathsf{Mac}_k(m^*) = t'$.

Query 1 has 1 block, but $M$ has $L \geq 2$ blocks, so $m \ne M$. Query 2 has $L - 1$ blocks, but $M$ has $L$, so $m' \ne M$.

Since no steps involve guessing or randomness, by 2a, $\mathsf{Mac}_k(M) = t'$ holds for all values of $k$. Thus, the success probability is 100%.

### 2c.

The attack in part 2a relies on chaining together two messages, $m$ and $m'$ to get $m^*$. Since $\ell^* = \ell +\ell'$, it is not possible for all three messages to have fixed length $\ell$. $\mathsf{Vrfy}$ would reject $m^*$. Similarly, in the attack in 2b, the first query has a length of 1. The second query has a length of $L-1$. Combined, the forged message is of length $L$. Since $L \ne L - 1$, the second query and the target cannot both be the same required length: if the fixed length is $L$, the oracle rejects the second query; otherwise, $\mathsf{Vrfy}$ rejects $M$. The attacks work by extending a message past its tag, but a fixed-length requirement blocks these attempts.

## 3. Implementation

Output of Demo:
```
--- 3b: Forgery Demo ---
Query: 66726f6d3d616c69636526746f3d6d61
Tag:   cf75d3cbf14b00559c134374ced338ee
Query: a319bcb9886d6138f3662d00f3e208de30303030266e6f74653d72656e742121
Tag:   07deb1f8a61458a9c2ca719c600b43f2
Forged Tag:     07deb1f8a61458a9c2ca719c600b43f2
Target Queried: False
Verify:         True

--- 3b: 100 Trials ---
Successful Forgeries: 100/100

--- 3c: Fixed-Length (3 blocks) ---
Attack failed at query 1: 66726f6d3d616c69636526746f3d6d61 (1 block)
Oracle error: oracle accepts only 3-block messages
```