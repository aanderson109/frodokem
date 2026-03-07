# Algorithms in FrodoKEM

## Supporting Algorithms

### Matrix Encode of Bit Strings

Encodes an integer that is strictly less than $2^B$ to be an element in $\mathbb{Z}_q$. It does this by multiplying it by $\frac{q}{2^B}$, or:
$$
\mathrm{ec}(k) := k \cdot \frac{q}{2^B} = \frac{kq}{2^B}
$$

### Matrix Decode of Bit Strings

An element in $\mathbb{Z}_q$ is divided by $\frac{q}{2^B}$ and rounded to the $B$ most significant bits of each entry.


## Algorithm 1 (`Frodo.Encode`)




# References

[1] https://frodokem.org/files/FrodoKEM-specification-20200930.pdf
