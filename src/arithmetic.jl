# Add
Base.:+(sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = add(sa1, sa2)
Base.:+(sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = add(sa, pa)
Base.:+(pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = add(sa, pa)
Base.:+(pa1::PlainArray{B, N}, pa2::PlainArray{B, N}) where {B, N} = add(pa1, pa2)
Base.:+(sa::SecureArray, scalar::Real) = add(sa, scalar)
Base.:+(scalar::Real, sa::SecureArray) = add(sa, scalar)
Base.:+(pa::PlainArray, scalar::Real) = add(pa, scalar)
Base.:+(scalar::Real, pa::PlainArray) = add(pa, scalar)

# Subtract
Base.:-(sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = subtract(sa1, sa2)
Base.:-(sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = subtract(sa, pa)
Base.:-(pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = subtract(pa, sa)
Base.:-(pa1::PlainArray{B, N}, pa2::PlainArray{B, N}) where {B, N} = subtract(pa1, pa2)
Base.:-(sa::SecureArray, scalar::Real) = subtract(sa, scalar)
Base.:-(scalar::Real, sa::SecureArray) = subtract(scalar, sa)
Base.:-(pa::PlainArray, scalar::Real) = subtract(pa, scalar)
Base.:-(scalar::Real, pa::PlainArray) = subtract(scalar, pa)
# Negate
Base.:-(sa::SecureArray) = negate(sa)
Base.:-(pa::PlainArray) = negate(pa)

# Multiply (scalar)
Base.:*(sa::SecureArray, scalar::Real) = multiply(sa, scalar)
Base.:*(scalar::Real, sa::SecureArray) = multiply(sa, scalar)
Base.:*(pa::PlainArray, scalar::Real) = multiply(pa, scalar)
Base.:*(scalar::Real, pa::PlainArray) = multiply(pa, scalar)

"""
    SecureArrayStyle <: Base.Broadcast.BroadcastStyle

Custom broadcast style for [`SecureArray`](@ref) and [`PlainArray`](@ref).

Since `SecureArray` and `PlainArray` are not `AbstractArray` subtypes and their elements
(ciphertexts) cannot be iterated individually, the standard broadcast machinery — which builds
a lazy `Broadcasted` expression tree and materializes it element-by-element — cannot be used.

Instead, we eagerly evaluate broadcast expressions by overriding
[`Base.Broadcast.broadcasted`](https://docs.julialang.org/en/v1/base/arrays/#Base.Broadcast.broadcasted)
for specific operations, returning the computed result
directly. This is the same approach Julia Base uses for `AbstractRange` operations in
[`base/broadcast.jl`](https://github.com/JuliaLang/julia/blob/d1c37793dd2ab0de6bca636e1d7f2ceb43150a9c/base/broadcast.jl#L1176), e.g.,
`broadcasted(::DefaultArrayStyle{1}, ::typeof(*), x::Number, r::LinRange)`.

We also override
[`Base.Broadcast.broadcastable`](https://docs.julialang.org/en/v1/base/arrays/#Base.Broadcast.broadcastable)
to return the objects as-is, since the default fallback (`collect(x)`) would attempt to call
`iterate` on them.

## Supported broadcast operations

- `.+` (element-wise add): `sa .+ sa`, `sa .+ pa`, `pa .+ sa`
- `.-` (element-wise subtract): `sa .- sa`, `sa .- pa`, `pa .- sa`
- `.*` (element-wise multiply): `sa .* sa`, `sa .* pa`, `pa .* sa`

## Example

```julia
sa1 .* sa2       # element-wise multiply (calls `multiply`)
```

See also: [`SecureArray`](@ref), [`PlainArray`](@ref), `multiply`
"""
struct SecureArrayStyle <: Base.Broadcast.BroadcastStyle end
Base.Broadcast.BroadcastStyle(::Type{<:SecureArray}) = SecureArrayStyle()
Base.Broadcast.BroadcastStyle(::Type{<:PlainArray}) = SecureArrayStyle()
# Win over scalars so e.g. `sa .* 2` stays in SecureArrayStyle (compare [SparseArrays.jl/src/higherorderfns.jl](https://github.com/JuliaSparse/SparseArrays.jl/blob/84b5114372a15d05b9a9a160d36f99b9a3d3cea6/src/higherorderfns.jl#L76))
Base.Broadcast.BroadcastStyle(s::SecureArrayStyle, ::Base.Broadcast.DefaultArrayStyle{0}) = s
# Prevent the default `broadcastable(x) = collect(x)` from calling `iterate` on ciphertexts.
Base.Broadcast.broadcastable(sa::SecureArray) = sa
Base.Broadcast.broadcastable(pa::PlainArray) = pa

# Element-wise add (a +* b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = add(sa1, sa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = add(sa, pa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = add(sa, pa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), pa1::PlainArray{B, N}, pa2::PlainArray{B, N}) where {B, N} = add(pa1, pa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), sa::SecureArray, scalar::Real) = add(sa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), scalar::Real, sa::SecureArray) = add(sa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), pa::PlainArray, scalar::Real) = add(pa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), scalar::Real, pa::PlainArray) = add(pa, scalar)

# Element-wise subtract (a .* b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = subtract(sa1, sa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = subtract(sa, pa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = subtract(pa, sa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), pa1::PlainArray{B, N}, pa2::PlainArray{B, N}) where {B, N} = subtract(pa1, pa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), sa::SecureArray, scalar::Real) = subtract(sa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), scalar::Real, sa::SecureArray) = subtract(scalar, sa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), pa::PlainArray, scalar::Real) = subtract(pa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), scalar::Real, pa::PlainArray) = subtract(scalar, pa)

# Element-wise multiply (a .* b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = multiply(sa1, sa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = multiply(sa, pa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = multiply(sa, pa)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), pa1::PlainArray{B, N}, pa2::PlainArray{B, N}) where {B, N} = multiply(pa1, pa2)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), sa::SecureArray, scalar::Real) = multiply(sa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), scalar::Real, sa::SecureArray) = multiply(sa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), pa::PlainArray, scalar::Real) = multiply(pa, scalar)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), scalar::Real, pa::PlainArray) = multiply(pa, scalar)

# Catch-all: any broadcast operation not listed above is unsupported.
# The implementations above are more specific and thus win for the defined operations.
# Without this, Julia's default `broadcasted` returns a lazy `Broadcasted` node whose `materialize` path calls
# `getindex` — which `SecureArray` does not support — producing a confusing `MethodError`.

@noinline function Base.Broadcast.broadcasted(::SecureArrayStyle, f::F, args...) where {F}
    throw(ArgumentError("broadcast operation `$f` is not supported for SecureArray/PlainArray. "))
end

# In-place broadcast assignment (`.=`) is not supported because ciphertexts cannot be mutated.
@noinline function Base.copyto!(dest::Union{SecureArray, PlainArray}, bc::Base.Broadcast.Broadcasted{SecureArrayStyle})
    throw(ArgumentError("in-place broadcast assignment (`.=`) is not supported for `$(typeof(dest))`."))
end

# Circular shift

function check_shifts(arr::Union{SecureArray, PlainArray}, shifts)
    if length(shifts) > ndims(arr)
        throw(ArgumentError("Got rotation index with length $(length(shifts)), expected $(ndims(arr))"))
    elseif length(shifts) < ndims(arr)
        shifts = vcat(collect(shifts), zeros(Integer, ndims(arr) - length(shifts)))
    end
    return shifts
end
"""
    circshift(sa::SecureArray, shifts)

Circularly shift, i.e., rotate the data in `sa` by `shifts` positions, similarly to Julia's
`circshift` for regular arrays.

Note: If `N` is greater than one, this operation increases the multiplicative level by two,
otherwise by one.

Note: To precompute all required rotation indexes, use `init_rotation!`.

See also: [`SecureArray`](@ref), [`init_rotation!`](@ref)
"""
function Base.circshift(sa::SecureArray, shifts)
    shifts = check_shifts(sa, shifts)

    if all(shifts .% size(sa) .== 0)
        return sa
    end

    rotate(sa, shifts)
end

function Base.circshift(pa::PlainArray, shifts)
    shifts = check_shifts(pa, shifts)

    if all(shifts .% size(pa) .== 0)
        return pa
    end

    data = collect(pa)
    shifted = circshift(data, shifts)
    PlainArray(shifted, pa.context)
end
