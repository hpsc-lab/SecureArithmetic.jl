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

# Multiply
Base.:*(sa1::SecureArray{B, N}, sa2::SecureArray{B, N}) where {B, N} = multiply(sa1, sa2)
Base.:*(sa::SecureArray{B, N}, pa::PlainArray{B, N}) where {B, N} = multiply(sa, pa)
Base.:*(pa::PlainArray{B, N}, sa::SecureArray{B, N}) where {B, N} = multiply(sa, pa)
Base.:*(sa::SecureArray, scalar::Real) = multiply(sa, scalar)
Base.:*(scalar::Real, sa::SecureArray) = multiply(sa, scalar)

# Circular shift
"""
    circshift(sa::SecureArray{<:AbstractCryptoBackend, N}, shift::NTuple{N, Integer})

Circularly shift, i.e., rotate the data in `sa` by `shift` positions, similarly to Julia's
`circshift` for regular arrays.

Note: If `N` is greater than one, this operation increases the multiplicative level by two,
otherwise by one.

Note: To precompute all required rotation indexes, use `init_array_rotation!`.

See also: [`SecureArray`](@ref), [`init_array_rotation!`](@ref)
"""
function Base.circshift(sa::SecureArray{<:AbstractCryptoBackend, N}, shift::NTuple{N, Integer}) where N
    if all(shift .% size(sa) .== 0)
        return sa
    end

    rotate(sa, shift)
end

"""
    circshift(sv::SecureVector, shift::Integer)

Circularly shift, i.e., rotate the data in `sv` by `shift` positions, similarly to Julia's
`circshift` for regular arrays.

Note: This operation increases the multiplicative level by one.

Note: To precompute all required rotation indexes, use `init_array_rotation!`.

See also: [`SecureVector`](@ref), [`init_array_rotation!`](@ref)
"""
function Base.circshift(sv::SecureVector, shift::Integer)
    rotate(sv, (shift,))
end
