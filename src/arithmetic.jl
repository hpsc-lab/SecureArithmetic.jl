# Add
Base.:+(sa1::SecureArray, sa2::SecureArray) = add(sa1, sa2)
Base.:+(sa::SecureArray, pa::PlainArray) = add(sa, pa)
Base.:+(pa::PlainArray, sa::SecureArray) = add(sa, pa)
Base.:+(sa::SecureArray, scalar::Real) = add(sa, scalar)
Base.:+(scalar::Real, sa::SecureArray) = add(sa, scalar)

# Subtract
Base.:-(sa1::SecureArray, sa2::SecureArray) = subtract(sa1, sa2)
Base.:-(sa::SecureArray, pa::PlainArray) = subtract(sa, pa)
Base.:-(pa::PlainArray, sa::SecureArray) = subtract(pa, sa)
Base.:-(sa::SecureArray, scalar::Real) = subtract(sa, scalar)
Base.:-(scalar::Real, sa::SecureArray) = subtract(scalar, sa)
# Negate
Base.:-(sa::SecureArray) = negate(sa)

# Multiply
Base.:*(sa1::SecureArray, sa2::SecureArray) = multiply(sa1, sa2)
Base.:*(sa::SecureArray, pa::PlainArray) = multiply(sa, pa)
Base.:*(pa::PlainArray, sa::SecureArray) = multiply(sa, pa)
Base.:*(sa::SecureArray, scalar::Real) = multiply(sa, scalar)
Base.:*(scalar::Real, sa::SecureArray) = multiply(sa, scalar)

# Circular shift
"""
    circshift(sa::SecureArray{<:AbstractCryptoBackend, N}, shift::NTuple{N, Integer})

Circularly shift, i.e., rotate the data in `sa` by `shift` positions, similarly to Julia's
`circshift` for regular arrays.

Note: If `N` is greater than one, this operation increases the multiplicative level by two.

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
    circshift(sv::SecureVector, shift::Union{Integer, Tuple{Integer}}; wrap_by = :not_set)

Circularly shift, i.e., rotate the data in `sv` by `shift` positions, similarly to Julia's
`circshift` for regular arrays. `wrap_by` indicates whether the rotation should be applied
with respect to the current data length of `sv` (`wrap_by :length`) or with respect to its
maximum capacity (`wrap_by = :capacity`). Default wrap_by = :not_set results in 
wrap_by = :capacity if data saved in a single ciphertext, otherwise in wrap_by = :length.

Note: If `sv`'s length is less than its capacity, wrapping by `:length` increases the
multiplicative depth of your algorithm by one and is more expensive to compute.

Note: To precompute all required rotation indexes, use `init_array_rotation!`.

See also: [`SecureVector`](@ref), [`length`](@ref), [`capacity`](@ref), [`init_array_rotation!`](@ref)
"""
function Base.circshift(sv::SecureVector, shift::Union{Integer, Tuple{Integer}}; wrap_by = :not_set)
    if wrap_by == :not_set 
        if length(sv.data) == 1
            wrap_by = :capacity
        else
            wrap_by = :length
        end
    elseif wrap_by == :capacity
        if length(sv.data) != 1
            wrap_by = :length
            @warn "Keyword wrap_by is reset to :length, because vector is split between many ciphertexts."
        end
    end
    if !(wrap_by in (:length, :capacity))
        throw(ArgumentError("Unsupported value '$wrap_by' passed to `wrap_by` (must be `:length` or `:capacity`)"))
    end
    rotate(sv, shift; wrap_by)
end
