# Array operations

This tutorial follows [`simple_matrix_operations.jl`](https://github.com/hpsc-lab/SecureArithmetic.jl/blob/main/examples/simple_matrix_operations.jl). It demonstrates the operations available on [`SecureMatrix`](@ref): 
- addition
- subtraction
- scalar multiplication
- element-wise multiplication
- circular shifts
- bootstrapping

The same API applies to [`SecureArray`](@ref) and [`SecureVector`](@ref), since [`SecureMatrix`](@ref) and [`SecureVector`](@ref) are aliases for [`SecureArray`](@ref).

## Choose a backend and prepare keys

SecureArithmetic exposes the same interface for encrypted and unencrypted computations. The unencrypted backend is useful for checking a computation's behavior; the OpenFHE backend performs the operations homomorphically.

Create a context, keys, and initialize the capabilities the computation needs. This doctest uses the unencrypted backend so it runs without OpenFHE setup; the [`simple_matrix_operations.jl`](https://github.com/hpsc-lab/SecureArithmetic.jl/blob/main/examples/simple_matrix_operations.jl) example uses the same API with an OpenFHE context.

```jldoctest array-operations
using SecureArithmetic

context = SecureContext(Unencrypted())
public_key, private_key = generate_keys(context)

init_multiplication!(context, private_key) # needed for multiplication
init_bootstrapping!(context, private_key)  # needed for bootstrap!
init_rotation!(context, private_key, (3, 3), (1, -1), (0, 1))
init_matrix_multiplication!(context, private_key, (3, 3), (3, 3)) # needed for `*`
# output

```

Rotation indexes used by [`circshift`](@ref) must be initialized in advance. The exact indexes depend on the shifts in your computation.

Matrix multiplication rotates internally as well, but you do not have to work out those shifts yourself: [`init_matrix_multiplication!`](@ref) takes the shapes of the two operands, in the same order as in `a * b`, and initializes exactly the rotation indexes the algorithm uses — including the ones that bring the operands into the packed layout the product is computed in and the ones that bring the result back out of it, unless you pass `packed = true` because the operands are packed already and the result should stay packed (see the section on packed arrays below). That is `3d - 2` shifts for a `d`-by-`d` left operand rather than all `d^2` shifts of the internal working vector, which matters at realistic ring dimensions where every rotation key is expensive to generate and store. Matrix multiplication additionally requires [`init_multiplication!`](@ref).

## Wrap, encrypt, and compute

Create ordinary Julia arrays, wrap them in [`PlainArray`](@ref) with the chosen context, then encrypt them with the public key:

```jldoctest array-operations
m1 = [0.25 0.5 0.75;
      1.0 2.0 3.0;
      4.0 5.0 6.0]
    
m2 = [6.0 5.0 4.0;
      3.0 2.0 1.0;
      0.75 0.5 0.25]

pm1 = PlainMatrix(m1, context)
pm2 = PlainMatrix(m2, context)
sm1 = encrypt(pm1, public_key);
sm2 = encrypt(pm2, public_key);
nothing
# output

```

Now perform the operations:

```jldoctest array-operations
sm_add = sm1 + sm2
sm_sub = sm1 - sm2
sm_scalar = sm1 * 4.0
sm_mult = sm1 .* sm2
sm_shift1 = circshift(sm1, (0, 1))
sm_shift2 = circshift(sm1, (1, -1))
sm_after_bootstrap = bootstrap!(sm1)
nothing
# output

```

Addition and subtraction work element by element. `sa1 * 4.0` multiplies every value by a scalar. For element-wise multiplication of two arrays, write `sa1 .* sa2`.

### Why `.*` for element-wise multiplication?

SecureArithmetic follows Julia's standard operator conventions. In Julia, `*` on matrices means linear algebra matrix multiplication, while `.*` means broadcasted, element-wise multiplication. SecureArray supports scalar `*` and uses `.*` to make element-wise multiplication explicit, consistent with ordinary Julia arrays. For example, if `A` and `B` are julia matrices, `A * B` performs matrix multiplication; `A .* B` multiplies corresponding entries element wise. SecureArray follows the same convention, and `*` on a [`SecureMatrix`](@ref) requires the keys from [`init_matrix_multiplication!`](@ref).

Julia also uses dotted operators for broadcasted array arithmetic (`.+`, `.-`, and `.*`). SecureArithmetic supports these operations as well. For the supported array-array operations, `+` and `.+` (likewise `-` and `.-`) both apply elementwise; Multiplication is the exception, where `.*` is the spelling for element-wise multiplication and `*` performs matrix multiplication.

[`circshift`](@ref) rotates values circularly along each dimension, so values shifted past one edge wrap around to the other. [`bootstrap!`](@ref) refreshes the ciphertext to increase the levels available for further homomorphic computation. It is an in-place operation: it refreshes `sm1` itself, and the returned value refers to the refreshed array.

## Decrypt and inspect results

Decrypt results with the private key when you are authorized to inspect them:

```jldoctest array-operations
result_pa = decrypt(sm_scalar, private_key)
# output
(3, 3)-shaped PlainArray{Unencrypted}:
  1.0   2.0   3.0
  4.0   8.0  12.0
 16.0  20.0  24.0
```

[`decrypt`](@ref) returns a [`PlainArray`](@ref).

```jldoctest array-operations
collect(result_pa)
# output
3×3 Matrix{Float64}:
  1.0   2.0   3.0
  4.0   8.0  12.0
 16.0  20.0  24.0
```

[`collect`](@ref) converts a [`PlainArray`](@ref) into an ordinary Julia [`Matrix`](https://docs.julialang.org/en/v1/base/arrays/#Base.Matrix), so the result can be used with any standard Julia operation. With the unencrypted backend, the same code gives exact arithmetic results; When using CKKS encryption decrypted values may differ slightly.


## Run the full example

The complete example configures an OpenFHE CKKS context, creates an unencrypted context, and runs all these operations with both. After you have installed OpenFHE.jl, run it from the package directory with:

```julia
using SecureArithmetic
include(joinpath(pkgdir(SecureArithmetic), "examples", "simple_matrix_operations.jl"))
```

## Packed arrays, and why `*` computes on them

Matrix multiplication implements the algorithm of [Jiang et al.](https://eprint.iacr.org/2018/1041.pdf), whose multiplicative depth does not depend on the matrix size at all: two plaintext-masked linear transformations plus one ciphertext-ciphertext multiplication. Whether a product actually gets that depth comes down to how the rotations inside the algorithm are carried out.

A [`SecureArray`](@ref) uses as many slots of its ciphertexts as it has elements, which is usually fewer than the batch size, i.e. the number of available slots in the ciphertext. A rotation of such an array cannot simply rotate the ciphertext: the slots beyond the data would be rotated in, so the wrap-around has to be reconstructed from two rotations combined through plaintext masks — and those masks cost a multiplicative level. Every single rotation of the algorithm would therefore cost one level, two rotations and two multiplications instead of one rotation.

[`PlainArrayPacked`](@ref) and [`SecureArrayPacked`](@ref) remove that overhead. A packed array
1. zero-pads every dimension to the next power of two, and
2. *tiles* the resulting block, i.e. repeats it, so that it fills its storage completely.

Since the batch size is always a power of two, as well as the padded matrix dimensions, the resulting block length divides the batch size exactly. Since there are now no empty slots at the end of the ciphertext, rotation does not entail masking anymore.

That saving is large enough to be worth having unconditionally, so `*` computes every product on the packed layout. It does not, however, impose that layout on its result: `*` keeps the layout of its operands, so a pair of flat [`SecureMatrix`](@ref) operands is packed on the way in and the result is unpacked again on the way out, while a pair of packed operands stays packed throughout. Packing a plaintext is free, and packing an array that is already encrypted costs a single multiplicative level — less than the masked rotations of an unpacked layout would cost the product itself; unpacking costs the same again, and nothing at all in the common cases.

Both operands have to be in the *same* layout. A product of one packed and one flat operand is rejected with an `ArgumentError` rather than silently converted, because which layout the result should then have would be arbitrary and the conversion would hide a multiplicative level. Convert explicitly first:

```julia
packed * SecureArrayPacked(flat)   # stay packed
SecureArray(packed) * flat         # go flat
```

What is left to decide is which rotation keys to generate. [`init_matrix_multiplication!`](@ref) takes the unpadded shapes of the operands, i.e. what [`size`](@ref) returns for either layout, plus `packed = true` when both operands are packed already — which is what leaves out the keys of the conversion:

```jldoctest packed-arrays
using SecureArithmetic

context = SecureContext(Unencrypted())
public_key, private_key = generate_keys(context)
init_multiplication!(context, private_key)

m1 = [0.25 0.5 0.75;
      1.0 2.0 3.0;
      4.0 5.0 6.0]

m2 = [6.0 5.0 4.0;
      3.0 2.0 1.0;
      0.75 0.5 0.25]

pm1 = PlainArrayPacked(m1, context)
pm2 = PlainArrayPacked(m2, context)
init_matrix_multiplication!(context, private_key, size(pm1), size(pm2); packed = true)

sm1 = encrypt(pm1, public_key)
sm2 = encrypt(pm2, public_key)
collect(decrypt(sm1 * sm2, private_key))
# output
3×3 Matrix{Float64}:
  3.5625   2.625   1.6875
 14.25    10.5     6.75
 43.5     33.0    22.5
```

Padding is invisible from the outside: [`size`](@ref) reports the shape you passed in, and [`collect`](@ref) crops back to it. Here the 3-by-3 operands are padded to 4-by-4 internally. A product of flat operands reports the same shape and the same values, but comes back as a [`SecureMatrix`](@ref), so it also works with `decrypt!` into a pre-allocated [`PlainMatrix`](@ref).

A matrix times a vector gives a vector back in either layout, as in Base. The algorithm multiplies the vector as a `d`-by-1 matrix, since `l = 1` divides `d`, but that reshape is undone again on the way out.

### What it costs and what it saves

How much is saved depends on whether the padded block fits into a single ciphertext. With `D` the padded dimension and `N = D^2`:

| | storage | rotations | depth of `d`-by-`d` product |
|:--|:--|:--|--:|
| `N < batch_size` | one ciphertext, block tiled `batch_size / N` times | one rotation, no level | 3 |
| `N == batch_size` | one ciphertext, exactly one copy | one rotation, no level | 3 |
| `N > batch_size` | `N / batch_size` ciphertexts, one copy | masked, one level each | 5 |

In the first two cases a square product of packed operands needs a multiplicative depth of 3 and a matrix-vector product one of 2, independent of the matrix size. Running the same algorithm on an unpacked layout would need 5 for a square product and `5 + 2 log2(d/l)` for a rectangular one — at `d = 16` that is a depth of 12 for a matrix-vector product, against 2 when packed. Measured operation counts for a 16-by-16 square product at a batch size of 4096: 93 multiplications and 90 rotations when packed, against 273 and 180 unpacked. That gap is what makes packing unconditional.

A product of *flat* operands pays the two conversions on top of those 3: it costs packing both operands, plus 3, plus unpacking the result. Each conversion is free when the dimension it has to pad is a power of two already, so the cheap cases stay cheap — and a matrix-vector product never pays for the unpack, because a vector result is always a contiguous prefix of its padded block. Keeping a chain of products in the packed layout avoids the conversions altogether.

In the third case there is no room for a second tile, so rotations still have to be masked and the depth is the same an unpacked array would have needed. Padding is still worthwhile there, because the storage is filled exactly and the rotation code avoids its partial-ciphertext cases.

The cost of packing is work, not depth: a dimension just above a power of two is padded up to the next one, so a 17-by-17 product is computed as a 32-by-32 one. That is the same trade-off `openfhe-numpy` makes.

### Chaining products

Every packed product comes back properly tiled, square or rectangular, so it can be fed straight back into another multiplication without a round trip through plaintext.

That is not automatic. For a rectangular product the last step of the algorithm aggregates the `d/l` sub-blocks of the padded block with a sequence of rotations. In the layout of the paper, where the block sits in a larger, zero-padded ciphertext, those rotations pull in zeros, so only the first sub-block ends up with the complete sum and the ones above it keep partial sums — the block is then no longer a faithful tile of the data. Tiling removes that: the storage is filled with copies of the block, so the same rotations wrap around into real data and the step becomes a full all-reduce in which every sub-block holds the complete sum.

### Packing an array that is already encrypted

[`PlainArrayPacked`](@ref) packs before encoding, so it is free — but it needs the data in the clear. An operand that is already encrypted and unpacked, such as the result of element-wise work, is converted by [`SecureArrayPacked(::SecureArray)`](@ref), which rebuilds the layout homomorphically: each run of contiguous slots is isolated with a plaintext mask, rotated to its padded offset, and the pieces are added up. The rotation indexes come from [`init_packing!`](@ref).

```jldoctest packed-arrays
unpacked = encrypt(PlainArray(m2, context), public_key)
init_packing!(context, private_key, size(m2))
repacked = SecureArrayPacked(unpacked)
collect(decrypt(repacked, private_key))
# output
3×3 Matrix{Float64}:
 6.0   5.0  4.0
 3.0   2.0  1.0
 0.75  0.5  0.25
```

The result is indistinguishable from `PlainArrayPacked(m2, context)` followed by [`encrypt`](@ref), down to the individual slots, so it can be used as an operand of a multiplication like any other packed array. This is what `*` does for you when it is handed a pair of flat operands; converting explicitly is worth it when the same operand is multiplied several times, so that it is converted once, when you want the product to stay packed, or when the conversion has to happen at a specific point of the level budget.

What the conversion costs depends on how much of the layout actually has to change. With `D` the padded first dimension, `d` the original one, and `N = prod(padded_shape)`:

| | multiplicative levels | rotations |
|:--|--:|--:|
| every dimension a power of two and `N >= batch_size` | 0 | none |
| `D == d` otherwise | 1 | tiling only, level-free |
| `D > d`, `N <= batch_size` | 1 | `l - 1` plus tiling, level-free |
| `D > d`, `N > batch_size` | 2 | `l - 1`, masked |

In the first case the unpacked storage already *is* a packed block and the conversion is a pure relabelling. In the last case the padded block spans several ciphertexts, so the rotations have to be masked as well and cost a level of their own, on top of the mask that isolates the runs.

The mask is not only there to separate the runs: it is also what makes the slots outside the data zero, which the packed layout relies on. The `capacity - length` tail of an unpacked array is zero only for a freshly encrypted one — a rotated array has data in those slots — and growing the storage clones a ciphertext rather than appending zeros. So the mask is needed even when every run stays where it is.

Converting is worth a level because the packed kernel is cheaper by more than that: a square product costs a depth of 3, against the 5 the same algorithm would need on an unpacked layout, so a conversion plus a product fits a depth of 4, or 3 when the conversion is free. A [`PlainArray`](@ref) can be converted too, with `PlainArrayPacked(::PlainArray)`, which needs no homomorphic work at all.

### Unpacking again

`SecureArray(::SecureArrayPacked)` is the inverse: it drops the zero padding and the tiling, so that the result is laid out exactly like a freshly encrypted flat array of that shape. It is the conversion `*` applies to the result of a product of flat operands, and its rotation indexes come from [`init_unpacking!`](@ref).

```jldoctest packed-arrays
init_unpacking!(context, private_key, size(m2))
collect(decrypt(SecureArray(repacked), private_key))
# output
3×3 Matrix{Float64}:
 6.0   5.0  4.0
 3.0   2.0  1.0
 0.75  0.5  0.25
```

It costs what packing costs, and for the same reason — the runs the padding drove apart are masked out, rotated back to their unpadded offsets and added up:

| | multiplicative levels | rotations |
|:--|--:|--:|
| `D == d`, or a vector, or a `d`-by-1 matrix | 0 | none |
| `D > d`, `N <= batch_size` | 1 | `l - 1`, level-free |
| `D > d`, `N > batch_size` | 2 | `l - 1`, masked |

The first row is wider than its counterpart for packing: when the first dimension needs no padding, the unpadded data already *is* a contiguous prefix of the padded block, so unpacking is a pure relabelling and the tiles are simply cropped away rather than having to be rebuilt. That is also why a matrix-vector product never pays for the unpack. A [`PlainArrayPacked`](@ref) is unpacked with `PlainArray(::PlainArrayPacked)`, which is free.

### Limitations

Adding a scalar to a packed array is not supported, since it would fill the zero padding that the multiplication relies on. Element-wise operations require both operands to agree on the padded shape as well as on the unpadded one.
