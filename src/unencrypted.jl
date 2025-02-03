"""
    Unencrypted

An alternative backend to use instead of [`OpenFHEBackend`](@ref) to experiment with
algorithms on unencrypted data.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref)
"""
struct Unencrypted <: AbstractCryptoBackend
    # No data fields required
end

"""
    generate_keys(context::SecureContext{<:Unencrypted})

Return public and private keys for use with unencrypted data.

See also: [`PublicKey`](@ref), [`PrivateKey`](@ref), [`SecureContext`](@ref),
[`Unencrypted`](@ref)
"""
function generate_keys(context::SecureContext{<:Unencrypted})
    PublicKey(context, nothing), PrivateKey(context, nothing)
end

"""
    init_multiplication!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)

An empty duplicate of [`init_multiplication!`](@ref) for unencrypted data.

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref), [`PrivateKey`](@ref),
[`init_multiplication!`](@ref)
"""
init_multiplication!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey) = nothing

"""
    init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey,
                   shape, shifts...)

An empty duplicate of [`init_rotation!`](@ref) for unencrypted data.

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref), [`PrivateKey`](@ref),
[`init_rotation!`](@ref)
"""
init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey,
               shape, shifts...) = nothing

"""
    init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)
              

An empty duplicate of [`init_bootstrapping!`](@ref) for unencrypted data.

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref), [`PrivateKey`](@ref),
[`init_bootstrapping!`](@ref)
"""
init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey) = nothing

"""
    PlainVector(data::Vector{<:Real}, context::SecureContext{<:Unencrypted})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:Unencrypted}`. Returns [`PlainVector`](@ref) with not encoded and
not encrypted data. The context can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).
        
See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
"""
function PlainVector(data::Vector{<:Real}, context::SecureContext{<:Unencrypted})
    PlainArray(data, context)
end

"""
    PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:Unencrypted})

Constructor for data type [`PlainMatrix`](@ref) takes an unencrypted `data` matrix and a `context`
object of type `SecureContext{<:Unencrypted}`. Returns [`PlainMatrix`](@ref) with not encoded and
not encrypted data. The context can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureMatrix`](@ref).
        
See also: [`PlainMatrix`](@ref), [`SecureMatrix`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
"""
function PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:Unencrypted})
    PlainArray(data, context)
end

"""
    PlainArray(data::Array{<:Real}, context::SecureContext{<:Unencrypted})

Constructor for data type [`PlainArray`](@ref) takes an unencrypted `data` array and a `context`
object of type `SecureContext{<:Unencrypted}`. Returns [`PlainArray`](@ref) with not encoded and
not encrypted data. The context can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureArray`](@ref).
        
See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
"""
function PlainArray(data::Array{<:Real}, context::SecureContext{<:Unencrypted})
    PlainArray(data, size(data), length(data), context)
end

function Base.show(io::IO, pa::PlainArray{<:Unencrypted})
    print(io, pa.data)
end

function Base.show(io::IO, ::MIME"text/plain", pa::PlainArray{<:Unencrypted})
    print(io, pa.shape, "-shaped PlainArray{Unencrypted}:\n")
    Base.print_matrix(io, pa.data)
end

"""
    collect(pa::PlainArray{<:Unencrypted})

Return the real-valued data contained in `pa`.

See also: [`PlainArray`](@ref)
"""
function Base.collect(pa::PlainArray{<:Unencrypted})
    pa.data
end

"""
    level(a::Union{SecureArray{<:Unencrypted}, PlainArray{<:Unencrypted}})

Return the number of scalings, referred to as the level, performed over `a`. For data type derived
from `Unencrypted`, the level is always equal to 0.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref)
"""
function level(a::Union{SecureArray{<:Unencrypted}, PlainArray{<:Unencrypted}})
    0
end

function encrypt_impl(data::Array{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:Unencrypted})
    SecureArray(data, size(data), length(data), context)
end

function encrypt_impl(plain_array::PlainArray{<:Unencrypted}, public_key::PublicKey)
    SecureArray(plain_array.data, size(plain_array), capacity(plain_array),
                plain_array.context)
end

function decrypt_impl!(plain_array::PlainArray{<:Unencrypted},
                       secure_array::SecureArray{<:Unencrypted}, private_key::PrivateKey)
    plain_array.data .= secure_array.data

    plain_array
end

function decrypt_impl(secure_array::SecureArray{<:Unencrypted}, private_key::PrivateKey)
    plain_array = PlainArray(similar(secure_array.data), size(secure_array), capacity(secure_array),
                             secure_array.context)

    decrypt!(plain_array, secure_array, private_key)
end

"""
    bootstrap!(secure_array::SecureArray{<:Unencrypted}, num_iterations = 1,
               precision = 0)
     
An empty duplicate of [`bootstrap!`](@ref) for unencrypted data.

See also: [`SecureArray`](@ref), [`Unencrypted`](@ref), [`bootstrap!`](@ref),
[`init_bootstrapping!`](@ref)
"""
bootstrap!(secure_array::SecureArray{<:Unencrypted}, num_iterations = 1,
           precision = 0) = secure_array


############################################################################################
# Arithmetic operations
############################################################################################

function add(sa1::SecureArray{<:Unencrypted}, sa2::SecureArray{<:Unencrypted})
    SecureArray(sa1.data .+ sa2.data, size(sa1), capacity(sa1), sa1.context)
end

function add(sa::SecureArray{<:Unencrypted}, pa::PlainArray{<:Unencrypted})
    SecureArray(sa.data .+ pa.data, size(sa), capacity(sa), sa.context)
end

function add(sa::SecureArray{<:Unencrypted}, scalar::Real)
    SecureArray(sa.data .+ scalar, size(sa), capacity(sa), sa.context)
end

function subtract(sa1::SecureArray{<:Unencrypted}, sa2::SecureArray{<:Unencrypted})
    SecureArray(sa1.data .- sa2.data, size(sa1), capacity(sa1), sa1.context)
end

function subtract(sa::SecureArray{<:Unencrypted}, pa::PlainArray{<:Unencrypted})
    SecureArray(sa.data .- pa.data, size(sa), capacity(sa), sa.context)
end

function subtract(pa::PlainArray{<:Unencrypted}, sa::SecureArray{<:Unencrypted})
    SecureArray(pa.data .- sa.data, size(sa), capacity(sa), sa.context)
end

function subtract(sa::SecureArray{<:Unencrypted}, scalar::Real)
    SecureArray(sa.data .- scalar, size(sa), capacity(sa), sa.context)
end

function subtract(scalar::Real, sa::SecureArray{<:Unencrypted})
    SecureArray(scalar .- sa.data, size(sa), capacity(sa), sa.context)
end

function negate(sa::SecureArray{<:Unencrypted})
    SecureArray(-sa.data, size(sa), capacity(sa), sa.context)
end

function multiply(sa1::SecureArray{<:Unencrypted}, sa2::SecureArray{<:Unencrypted})
    SecureArray(sa1.data .* sa2.data, size(sa1), capacity(sa1), sa1.context)
end

function multiply(sa::SecureArray{<:Unencrypted}, pa::PlainArray{<:Unencrypted})
    SecureArray(sa.data .* pa.data, size(sa), capacity(sa), sa.context)
end

function multiply(sa::SecureArray{<:Unencrypted}, scalar::Real)
    SecureArray(sa.data .* scalar, size(sa), capacity(sa), sa.context)
end

function rotate(sa::SecureArray{<:Unencrypted, N}, shift) where N
    SecureArray(circshift(sa.data, shift), size(sa), capacity(sa), sa.context)
end
