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

Base.:>>>(sa::SecureArray, shift::Integer) = circshift(sa, shift)

# end-off shift
"""
    eoshift(sa::SecureArray, shifts)

End-off shift, i.e., i.e. add `shifts` many zeros to the left of the data in `sa` and remove `shifts` elements from the right.

Note: To precompute all required rotation indexes, use `init_rotation!`.

See also: [`SecureArray`](@ref), [`init_rotation!`](@ref), [`circshift`](@ref), [Fortran EOSHIFT](https://gcc.gnu.org/onlinedocs/gfortran/EOSHIFT.html)
"""
function eoshift(sa::SecureArray, shifts)
    mask = zeros(length(sa))
    if shifts >= 0
        mask[1+shifts:end] .= 1
    else
        mask[1:end+shifts] .= 1
    end
    return circshift(sa, (shifts,)) * PlainArray(mask, sa.context)
end

Base.:>>(sa::SecureArray, shift::Integer) = eoshift(sa, shift)

"""
    running_sums(v::SecureArray)

Computes the running sums r such that ``r[i] = \\sum_{k=0}^i v[k] \\tex{for} \\i in [n]``.

See also: [Halevi, S., & Shoup, V. (2014). Algorithms in HElib](https://eprint.iacr.org/2014/106)
"""

function running_sums(v::SecureArray{<:OpenFHEBackend})
    n = length(v)
    w = v
    e = 1
    while e < n
        w = w + (w >> e)
        e = 2 * e
    end
    return w
end

"""
    total_sums(v::SecureArray)

Computes the total sums t such that ``t[i] = \\sum_{k=0}^{n-1} v[k] \\tex{for} \\i in [n]``.

See also: [Halevi, S., & Shoup, V. (2014). Algorithms in HElib](https://eprint.iacr.org/2014/106)
"""
function total_sums(v::SecureArray{<:OpenFHEBackend})
    n = length(v)
    w = v
    e = 1
    for j in (ndigits(n, base=2) - 2):-1:0
        w = w + (w >>> e)
        e = 2 * e
        if n >> j & 1 == 1
            w = v + (w >>> 1)
            e = e + 1
        end
    end
    return w
end