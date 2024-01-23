# Add
Base.:+(sv1::SecureVector, sv2::SecureVector) = add(sv1, sv2)
Base.:+(sv::SecureVector, pv::PlainVector) = add(sv, pv)
Base.:+(pv::PlainVector, sv::SecureVector) = add(sv, pv)
Base.:+(sv::SecureVector, scalar::Real) = add(sv, scalar)
Base.:+(scalar::Real, sv::SecureVector) = add(sv, scalar)

# Subtract
Base.:-(sv1::SecureVector, sv2::SecureVector) = subtract(sv1, sv2)
Base.:-(sv::SecureVector, pv::PlainVector) = subtract(sv, pv)
Base.:-(pv::PlainVector, sv::SecureVector) = subtract(pv, sv)
Base.:-(sv::SecureVector, scalar::Real) = subtract(sv, scalar)
Base.:-(scalar::Real, sv::SecureVector) = subtract(scalar, sv)

# Negate
Base.:-(sv::SecureVector) = negate(sv)

# Multiply
Base.:*(sv1::SecureVector, sv2::SecureVector) = multiply(sv1, sv2)
Base.:*(sv::SecureVector, pv::PlainVector) = multiply(sv, pv)
Base.:*(pv::PlainVector, sv::SecureVector) = multiply(sv, pv)
Base.:*(sv::SecureVector, scalar::Real) = multiply(sv, scalar)
Base.:*(scalar::Real, sv::SecureVector) = multiply(sv, scalar)

# Circular shift
"""
    circshift(sv::SecureVector, shift; wrap_by = :capacity)

Circularly shift, i.e., rotate the data in `sv` by `shift` positions, similarly to Julia's
`circshift` for regular arrays. `wrap_by` indicates whether the rotation should be applied
with respect to the current data length of `sv` (`wrap_by :length`) or with respect to its
maximum capacity (`wrap_by = :capacity`).

Note: If `sv`'s length is less than its capacity, wrapping by `:length` increases the
multiplicative depth of your algorithm by one and is more expensive to compute. Furthermore,
one additional rotation is applied with a shift of
`-sign(shift) * (length(sv) - abs(shift))`.

See also: [`SecureVector`](@ref), [`length`](@ref), [`capacity`](@ref)
"""
function Base.circshift(sv::SecureVector, shift::Integer; wrap_by = :capacity)
    if !(wrap_by in (:length, :capacity))
        throw(ArgumentError("Unsupported value '$wrap_by' passed to `wrap_by` (must be `:length` or `:capacity`)"))
    end

    if shift == 0
        return sv
    end

    rotate(sv, shift; wrap_by)
end
