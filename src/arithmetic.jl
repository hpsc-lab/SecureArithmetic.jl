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

function running_sums(v::SecureArray)
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
function total_sums(v::SecureArray)
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

"""
    full_replication(v::SecureArray{<:OpenFHEBackend})

Replicates a single entry across the entire array. 
This procedure uses multiplicative masking to extract the entry, then total-sums to replicate it across the vector.

Running time:  O(n) additions, rotations, and multiplicative masking
Depth: O(log n) additions, rotations, and masking.

See also: [`total_sums`](@ref)
"""
function full_replication(v::SecureArray)
    n = length(v)
    h = log(2, n)
    l = Int(floor(h)) # 2^l shall be the largest power of 2 not exceeding n
    # TODO: Implement Section 4.2.2 A Shallower Full Replication Procedure in order to save on masking depth (O(log log n) instead of O(log n))
    if l == h
        return recursive_replicate(v, l)
    else
        # construct v1 such that it equals v in the first 2^l positions and is 0 everywhere else, 
        mask = PlainArray(vcat(ones(2^l), zeros(n-2^l)), v.context)
        v1 = v * mask
        
        # and v2 such that it equals v in the last n − 2^l positions and is 0 everywhere else, i.e. v1+v2=v --> v2 = v-v1
        v2 = v-v1

        # recursive_replicate(v1, l) gives us vectors w_0, ... , w_{2^l−1}, where w_i is v[i] in the first 2^l positions, and 0 everywhere else
        # recursive_replicate(v2 >>> -2^l, l) gives us vectors w_0, ... , w_{2^l-1}. 
        # We only care for the first n-2^l vectors, where w_i is v[i+2^l] in the first 2^l positions, and 0 everywhere else
        return [w + ((w*mask) >> 2^l) for w in vcat(recursive_replicate(v1, l), recursive_replicate(v2 >>> -2^l, l)[1:n-2^l])]
    end
end

function recursive_replicate(w::SecureArray, h)
    n = length(w)
    if h == 0
        return [w]
    end
    
   mask = [(i-1) >> (h - 1) & 1 for i in 1:n]
   w1 = w * PlainArray(mask, w.context)
   w0 = w-w1
   wL = w0 + (w0 >>> 2^(h-1))
   wR = w1 + (w1 >>> -2^(h-1))

   return vcat(recursive_replicate(wL, h-1), recursive_replicate(wR, h-1))
end