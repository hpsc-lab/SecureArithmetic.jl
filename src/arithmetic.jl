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


############################################################################################
# Matrix
############################################################################################

# Add
Base.:+(sm1::SecureMatrix, sm2::SecureMatrix) = add(sm1, sm2)
Base.:+(sm::SecureMatrix, pm::PlainMatrix) = add(sm, pm)
Base.:+(pm::PlainMatrix, sm::SecureMatrix) = add(sm, pm)
Base.:+(sm::SecureMatrix, scalar::Real) = add(sm, scalar)
Base.:+(scalar::Real, sm::SecureMatrix) = add(sm, scalar)

# Subtract
Base.:-(sm1::SecureMatrix, sm2::SecureMatrix) = subtract(sm1, sm2)
Base.:-(sm::SecureMatrix, pm::PlainMatrix) = subtract(sm, pm)
Base.:-(pm::PlainMatrix, sm::SecureMatrix) = subtract(pm, sm)
Base.:-(sm::SecureMatrix, scalar::Real) = subtract(sm, scalar)
Base.:-(scalar::Real, sm::SecureMatrix) = subtract(scalar, sm)

# Negate
Base.:-(sm::SecureMatrix) = negate(sm)

# Multiply
Base.:*(sm1::SecureMatrix, sm2::SecureMatrix) = multiply(sm1, sm2)
Base.:*(sm::SecureMatrix, pm::PlainMatrix) = multiply(sm, pm)
Base.:*(pm::PlainMatrix, sm::SecureMatrix) = multiply(sm, pm)
Base.:*(sm::SecureMatrix, scalar::Real) = multiply(sm, scalar)
Base.:*(scalar::Real, sm::SecureMatrix) = multiply(sm, scalar)

# Circular shift
function Base.circshift(sm::SecureMatrix, shift::Tuple{Integer, Integer})
    if shift[1] % size(sm, 1) == 0 && shift[2] % size(sm, 2) == 0
        return sm
    end

    rotate(sm, shift)
end


############################################################################################
# Array
############################################################################################

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
function Base.circshift(sa::SecureArray, shift::Union{Integer, Tuple})
    if all(shift .% size(sa) .== 0)
        return sa
    end

    rotate(sa, shift)
end
