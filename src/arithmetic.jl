# Add
Base.:+(sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = add(sa1, sa2)
Base.:+(sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = add(sa, pa)
Base.:+(pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = add(sa, pa)
Base.:+(sa::SecureArray, scalar::Real) = add(sa, scalar)
Base.:+(scalar::Real, sa::SecureArray) = add(sa, scalar)

# Subtract
Base.:-(sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = subtract(sa1, sa2)
Base.:-(sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = subtract(sa, pa)
Base.:-(pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = subtract(pa, sa)
Base.:-(sa::SecureArray, scalar::Real) = subtract(sa, scalar)
Base.:-(scalar::Real, sa::SecureArray) = subtract(scalar, sa)
# Negate
Base.:-(sa::SecureArray) = negate(sa)

# Multiply (scalar)
Base.:*(sa::SecureArray, scalar::Real) = multiply(sa, scalar)
Base.:*(scalar::Real, sa::SecureArray) = multiply(sa, scalar)

"""
    SecureArrayStyle <: Base.Broadcast.BroadcastStyle

Custom broadcast style for [`SecureArray`](@ref) and [`PlainArray`](@ref).

Since `SecureArray` and `PlainArray` are not `AbstractArray` subtypes and their elements
(ciphertexts) cannot be iterated individually, the standard broadcast machinery — which builds
a lazy `Broadcasted` expression tree and materializes it element-by-element — cannot be used.

Instead, we eagerly evaluate broadcast expressions by overriding
[`Base.Broadcast.broadcasted`](@ref) for specific operations, returning the computed result
directly. This is the same approach Julia Base uses for `AbstractRange` operations in
[`base/broadcast.jl`](https://github.com/JuliaLang/julia/blob/d1c37793dd2ab0de6bca636e1d7f2ceb43150a9c/base/broadcast.jl#L1176), e.g.,
`broadcasted(::DefaultArrayStyle{1}, ::typeof(*), x::Number, r::LinRange)`.

We also override [`Base.Broadcast.broadcastable`](@ref) to return the objects as-is, since the
default fallback (`collect(x)`) would attempt to call `iterate` on them.

## Supported broadcast operations

- `.*` (element-wise multiply): `sa .* sa`, `sa .* pa`, `pa .* sa`, `pa .* pa`

## Example

```jldoctest
sa1 .* sa2       # element-wise multiply (calls `multiply`)
sa1 * sa2         # matrix multiply for SecureMatrix (calls `row_mat_times_mat`)
```

See also: [`SecureArray`](@ref), [`PlainArray`](@ref), [`multiply`](@ref)
"""
struct SecureArrayStyle <: Base.Broadcast.BroadcastStyle end
Base.Broadcast.BroadcastStyle(::Type{<:SecureArray}) = SecureArrayStyle()
Base.Broadcast.BroadcastStyle(::Type{<:PlainArray}) = SecureArrayStyle()
Base.Broadcast.BroadcastStyle(s::SecureArrayStyle, ::Base.Broadcast.DefaultArrayStyle{0}) = s
# Prevent the default `broadcastable(x) = collect(x)` from calling `iterate` on ciphertexts.
Base.Broadcast.broadcastable(sa::SecureArray) = sa
Base.Broadcast.broadcastable(pa::PlainArray) = pa

# Element-wise multiply (a .* b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), a::SecureArray{B, N}, b::SecureArray{B, N}) where {B, N} = multiply(a, b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), a::SecureArray{B, N}, b::PlainArray{B, N}) where {B, N} = multiply(a, b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), a::PlainArray{B, N}, b::SecureArray{B, N}) where {B, N} = multiply(b, a)

# Circular shift
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
    if length(shifts) > ndims(sa)
        throw(ArgumentError("Got rotation index with length $(length(shifts)), expected $(ndims(sa))"))
    elseif length(shifts) < ndims(sa)
        shifts = vcat(collect(shifts), zeros(Integer, ndims(sa) - length(shifts)))
    end

    if all(shifts .% size(sa) .== 0)
        return sa
    end

    rotate(sa, shifts)
end
