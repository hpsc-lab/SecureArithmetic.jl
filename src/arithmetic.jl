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
for specific operations, returning the computed result directly. 
    This is the same approach Julia Base uses for `AbstractRange` operations in
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


############################################################################################
# Packed arrays
############################################################################################

# Element-wise ops forward to the inner array and keep the packed metadata. Operands must
# agree on both the unpadded and the padded shape, so the zero padding stays zero and the
# tiling period is unchanged.
function packed_elementwise(op, a::AnyArrayPacked, b::AnyArrayPacked)
    if size(a) != size(b)
        throw(DimensionMismatch("shapes $(size(a)) and $(size(b)) do not match"))
    end
    if a.padded_shape != b.padded_shape
        throw(DimensionMismatch("padded shapes $(a.padded_shape) and $(b.padded_shape) do not match"))
    end
    pack_result(op(a.array, b.array), size(a), a.padded_shape)
end

Base.:+(a::AnyArrayPacked{B, N}, b::AnyArrayPacked{B, N}) where {B, N} = packed_elementwise(+, a, b)
Base.:-(a::AnyArrayPacked{B, N}, b::AnyArrayPacked{B, N}) where {B, N} = packed_elementwise(-, a, b)
Base.:-(a::AnyArrayPacked) = pack_result(-a.array, size(a), a.padded_shape)

# Scaling is safe: it leaves the zero padding zero and the tiling intact. Adding a scalar
# would fill the padding, which a later packed matrix multiplication relies on being zero,
# so it is deliberately not defined.
Base.:*(a::AnyArrayPacked, scalar::Real) = pack_result(a.array * scalar, size(a), a.padded_shape)
Base.:*(scalar::Real, a::AnyArrayPacked) = a * scalar

Base.Broadcast.BroadcastStyle(::Type{<:PlainArrayPacked}) = SecureArrayStyle()
Base.Broadcast.BroadcastStyle(::Type{<:SecureArrayPacked}) = SecureArrayStyle()
Base.Broadcast.broadcastable(a::PlainArrayPacked) = a
Base.Broadcast.broadcastable(a::SecureArrayPacked) = a

@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(+), a::AnyArrayPacked{B, N}, b::AnyArrayPacked{B, N}) where {B, N} = packed_elementwise(+, a, b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(-), a::AnyArrayPacked{B, N}, b::AnyArrayPacked{B, N}) where {B, N} = packed_elementwise(-, a, b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), a::AnyArrayPacked{B, N}, b::AnyArrayPacked{B, N}) where {B, N} = packed_elementwise((x, y) -> x .* y, a, b)
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), a::AnyArrayPacked, scalar::Real) = a * scalar
@inline Base.Broadcast.broadcasted(::SecureArrayStyle, ::typeof(*), scalar::Real, a::AnyArrayPacked) = a * scalar

# Matrix Multiplication
# For matrices in column-major order, we have to swap the arguments order
# Matrix multiplication always runs on the packed layout, 
# so a pair of flat operands is packed with `as_packed` on the way in and unpacked again
# with `as_unpacked` on the way out. This is still cheaper than the jiang algorithm on flat arrays directly
Base.:*(sm1::AnyPackedMatrix{B}, sm2::AnyPackedMatrix{B}) where {B} = SecureArithmetic.row_mat_times_mat(sm2, sm1)
Base.:*(sm1::AnyFlatMatrix{B}, sm2::AnyFlatMatrix{B}) where {B} = as_unpacked(SecureArithmetic.row_mat_times_mat(as_packed(sm2), as_packed(sm1)))
# d×d-Matrix * d-Vector is computed as d×d-Matrix * d×1-Matrix, where l=1 divides d, and the
# reshape is undone on the way out so that a vector operand gives a vector back, as in Base.
Base.:*(sm::AnyPackedMatrix{B}, sv::AnyPackedVector{B}) where {B} = reshape(SecureArithmetic.row_mat_times_mat(reshape(sv, (length(sv), 1)), sm), (length(sv),))
Base.:*(sm::AnyFlatMatrix{B}, sv::AnyFlatVector{B}) where {B} = as_unpacked(reshape(SecureArithmetic.row_mat_times_mat(reshape(as_packed(sv), (length(sv), 1)), as_packed(sm)), (length(sv),)))

# Mixing the layouts in one product is not supported, the implicit conversion would hide a multiplicative level. 
# Spelled out as methods rather than left to fall through, so that the error says what to do instead of being a
# bare `MethodError`.
@noinline function mixed_layout_error(a, b)
    throw(ArgumentError("cannot multiply a packed and a flat operand ($(typeof(a)) and " *
                        "$(typeof(b))): both operands of `*` must be in the same layout. " *
                        "Pack the flat one with `PlainArrayPacked`/`SecureArrayPacked`, or " *
                        "unpack the packed one with `PlainArray`/`SecureArray`."))
end

Base.:*(a::AnyPackedMatrix{B}, b::AnyFlatMatrix{B}) where {B} = mixed_layout_error(a, b)
Base.:*(a::AnyFlatMatrix{B}, b::AnyPackedMatrix{B}) where {B} = mixed_layout_error(a, b)
Base.:*(a::AnyPackedMatrix{B}, b::AnyFlatVector{B}) where {B} = mixed_layout_error(a, b)
Base.:*(a::AnyFlatMatrix{B}, b::AnyPackedVector{B}) where {B} = mixed_layout_error(a, b)
