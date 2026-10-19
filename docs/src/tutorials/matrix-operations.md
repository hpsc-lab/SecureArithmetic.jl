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
# output

```

Rotation indexes used by [`circshift`](@ref) must be initialized in advance. The exact indexes depend on the shifts in your computation.

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

SecureArithmetic follows Julia's standard operator conventions. In Julia, `*` on matrices means linear algebra matrix multiplication, while `.*` means broadcasted, element-wise multiplication. SecureArray supports scalar `*` and uses `.*` to make element-wise multiplication explicit, consistent with ordinary Julia arrays. For example, if `A` and `B` are julia matrices, `A * B` performs matrix multiplication; `A .* B` multiplies corresponding entries element wise. SecureArray currently provides the latter operation for SecureArrays, rather than matrix multiplication.

Julia also uses dotted operators for broadcasted array arithmetic (`.+`, `.-`, and `.*`). SecureArithmetic supports these operations as well. For the supported array-array operations, `+` and `.+` (likewise `-` and `.-`) both apply elementwise; Multiplication is the execption where only `.*` is the spelling to use for element-wise multiplication and `*` will be matrix multiplication but is not implemented yet. 

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
