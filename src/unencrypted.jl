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
    init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey, shifts)

An empty duplicate of [`init_rotation!`](@ref) for unencrypted data.

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref), [`PrivateKey`](@ref),
[`init_rotation!`](@ref)
"""
init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey, shifts) = nothing

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
    PlainVector(data, length(data), length(data), context)
end

function Base.show(io::IO, v::PlainVector{<:Unencrypted})
    print(io, v.data[1:v.length])
end

function Base.show(io::IO, ::MIME"text/plain", v::PlainVector{<:Unencrypted})
    print(io, v.length, "-element PlainVector{Unencrypted}:\n")
    Base.print_matrix(io, v.data[1:v.length])
end

"""
    collect(v::PlainVector{<:Unencrypted})

Return the real-valued data contained in `v`.

See also: [`PlainVector`](@ref)
"""
function Base.collect(v::PlainVector{<:Unencrypted})
    v.data
end

"""
    level(v::Union{SecureVector{<:Unencrypted}, PlainVector{<:Unencrypted}})

Return the number of scalings, referred to as the level, performed over `v`. For data type derived
from `Unencrypted`, the level is always equal to 0.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref)
"""
function level(v::Union{SecureVector{<:Unencrypted}, PlainVector{<:Unencrypted}})
    0
end

function encrypt_impl(data::Vector{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:Unencrypted})
    SecureVector(data, length(data), length(data), context)
end

function encrypt_impl(plain_vector::PlainVector{<:Unencrypted}, public_key::PublicKey)
    SecureVector(plain_vector.data, length(plain_vector), capacity(plain_vector),
                 plain_vector.context)
end

function decrypt_impl!(plain_vector::PlainVector{<:Unencrypted},
                       secure_vector::SecureVector{<:Unencrypted}, private_key::PrivateKey)
    plain_vector.data .= secure_vector.data

    plain_vector
end

function decrypt_impl(secure_vector::SecureVector{<:Unencrypted}, private_key::PrivateKey)
    plain_vector = PlainVector(similar(secure_vector.data), length(secure_vector),
                               capacity(secure_vector), secure_vector.context)

    decrypt!(plain_vector, secure_vector, private_key)
end

"""
    bootstrap!(secure_vector::SecureVector{<:Unencrypted})
     
An empty duplicate of [`bootstrap!`](@ref) for unencrypted data.

See also: [`SecureVector`](@ref), [`Unencrypted`](@ref), [`bootstrap!`](@ref),
[`init_bootstrapping!`](@ref)
"""
bootstrap!(secure_vector::SecureVector{<:Unencrypted}) = secure_vector


############################################################################################
# Arithmetic operations
############################################################################################

function add(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.data .+ sv2.data, length(sv1), capacity(sv1), sv1.context)
end

function add(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.data .+ pv.data, length(sv), capacity(sv), sv.context)
end

function add(sv::SecureVector{<:Unencrypted}, scalar::Real)
    SecureVector(sv.data .+ scalar, length(sv), capacity(sv), sv.context)
end

function subtract(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.data .- sv2.data, length(sv1), capacity(sv1), sv1.context)
end

function subtract(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.data .- pv.data, length(sv), capacity(sv), sv.context)
end

function subtract(pv::PlainVector{<:Unencrypted}, sv::SecureVector{<:Unencrypted})
    SecureVector(pv.data .- sv.data, length(sv), capacity(sv), sv.context)
end

function subtract(sv::SecureVector{<:Unencrypted}, scalar::Real)
    SecureVector(sv.data .- scalar, length(sv), capacity(sv), sv.context)
end

function subtract(scalar::Real, sv::SecureVector{<:Unencrypted})
    SecureVector(scalar .- sv.data, length(sv), capacity(sv), sv.context)
end

function negate(sv::SecureVector{<:Unencrypted})
    SecureVector(-sv.data, length(sv), capacity(sv), sv.context)
end

function multiply(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.data .* sv2.data, length(sv1), capacity(sv1), sv1.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.data .* pv.data, length(sv), capacity(sv), sv.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, scalar::Real)
    SecureVector(sv.data .* scalar, length(sv), capacity(sv), sv.context)
end

function rotate(sv::SecureVector{<:Unencrypted}, shift; wrap_by)
    # `wrap_by` can be ignored since here length is always equal to capacity
    SecureVector(circshift(sv.data, shift), length(sv), capacity(sv), sv.context)
end


############################################################################################
# Matrix
############################################################################################
init_matrix_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey,
                      shifts::Vector{Tuple{Int, Int}}, shape::Tuple{Int, Int}) = nothing

function PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:Unencrypted})
    PlainMatrix(data, size(data), length(data), context)
end

function Base.show(io::IO, m::PlainMatrix{<:Unencrypted})
    print(io, m.data[1:m.shape[1], 1:m.shape[2]])
end

function Base.show(io::IO, ::MIME"text/plain", m::PlainMatrix{<:Unencrypted})
    print(io, m.shape, "-element PlainMatrix{Unencrypted}:\n")
    Base.print_matrix(io, m.data[1:m.shape[1], 1:m.shape[2]])
end

function Base.collect(m::PlainMatrix{<:Unencrypted})
    m.data
end

function level(m::Union{SecureMatrix{<:Unencrypted}, PlainMatrix{<:Unencrypted}})
    0
end

function encrypt_impl(data::Matrix{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:Unencrypted})
    SecureMatrix(data, size(data), length(data), context)
end

function encrypt_impl(plain_matrix::PlainMatrix{<:Unencrypted}, public_key::PublicKey)
    SecureMatrix(plain_matrix.data, size(plain_matrix), capacity(plain_matrix),
                 plain_matrix.context)
end

function decrypt_impl!(plain_matrix::PlainMatrix{<:Unencrypted},
                       secure_matrix::SecureMatrix{<:Unencrypted}, private_key::PrivateKey)
    plain_matrix.data .= secure_matrix.data

    plain_matrix
end

function decrypt_impl(secure_matrix::SecureMatrix{<:Unencrypted}, private_key::PrivateKey)
    plain_matrix = PlainMatrix(similar(secure_matrix.data), size(secure_matrix),
                               capacity(secure_matrix), secure_matrix.context)

    decrypt!(plain_matrix, secure_matrix, private_key)
end

bootstrap!(secure_matrix::SecureMatrix{<:Unencrypted}) = secure_matrix


############################################################################################
# Arithmetic operations
############################################################################################

function add(sm1::SecureMatrix{<:Unencrypted}, sm2::SecureMatrix{<:Unencrypted})
    SecureMatrix(sm1.data .+ sm2.data, size(sm1), capacity(sm1), sm1.context)
end

function add(sm::SecureMatrix{<:Unencrypted}, pm::PlainMatrix{<:Unencrypted})
    SecureMatrix(sm.data .+ pm.data, size(sm), capacity(sm), sm.context)
end

function add(sm::SecureMatrix{<:Unencrypted}, scalar::Real)
    SecureMatrix(sm.data .+ scalar, size(sm), capacity(sm), sm.context)
end

function subtract(sm1::SecureMatrix{<:Unencrypted}, sm2::SecureMatrix{<:Unencrypted})
    SecureMatrix(sm1.data .- sm2.data, size(sm1), capacity(sm1), sm1.context)
end

function subtract(sm::SecureMatrix{<:Unencrypted}, pm::PlainMatrix{<:Unencrypted})
    SecureMatrix(sm.data .- pm.data, size(sm), capacity(sm), sm.context)
end

function subtract(pm::PlainMatrix{<:Unencrypted}, sm::SecureMatrix{<:Unencrypted})
    SecureMatrix(pm.data .- sm.data, size(sm), capacity(sm), sm.context)
end

function subtract(sm::SecureMatrix{<:Unencrypted}, scalar::Real)
    SecureMatrix(sm.data .- scalar, size(sm), capacity(sm), sm.context)
end

function subtract(scalar::Real, sm::SecureMatrix{<:Unencrypted})
    SecureMatrix(scalar .- sm.data, size(sm), capacity(sm), sm.context)
end

function negate(sm::SecureMatrix{<:Unencrypted})
    SecureMatrix(-sm.data, size(sm), capacity(sm), sm.context)
end

function multiply(sm1::SecureMatrix{<:Unencrypted}, sm2::SecureMatrix{<:Unencrypted})
    SecureMatrix(sm1.data .* sm2.data, size(sm1), capacity(sm1), sm1.context)
end

function multiply(sm::SecureMatrix{<:Unencrypted}, pm::PlainMatrix{<:Unencrypted})
    SecureMatrix(sm.data .* pm.data, size(sm), capacity(sm), sm.context)
end

function multiply(sm::SecureMatrix{<:Unencrypted}, scalar::Real)
    SecureMatrix(sm.data .* scalar, size(sm), capacity(sm), sm.context)
end

function rotate(sm::SecureMatrix{<:Unencrypted}, shift)
    # `wrap_by` can be ignored since here length is always equal to capacity
    SecureMatrix(circshift(sm.data, shift), size(sm), capacity(sm), sm.context)
end
