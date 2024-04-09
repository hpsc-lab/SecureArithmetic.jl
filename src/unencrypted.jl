struct Unencrypted <: AbstractCryptoBackend
    # No data fields required
end

function generate_keys(context::SecureContext{<:Unencrypted})
    PublicKey(context, nothing), PrivateKey(context, nothing)
end

init_multiplication!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey) = nothing
init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey, shifts) = nothing
init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey) = nothing

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

function Base.collect(v::PlainVector{<:Unencrypted})
    v.data
end

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

function PlainMatrix(data::Vector{Vector{<:Real}}, context::SecureContext{CryptoBackendT <: Unencrypted}) where CryptoBackendT
    plain_vectors = PlainVector.(data, context)
    PlainMatrix(plain_vectors, length(data), context)
end
function PlainMatrix(data::Matrix{RealT <: Real}, context::SecureContext{CryptoBackendT <: Unencrypted}) where {CryptoBackendT, RealT}
    plain_vectors = Vector{PlainVector{CryptoBackendT, Vector{RealT}}}
    column_length, row_length = size(data)    
    for i in range(0, column_length-1)
        # not optimal?
        append!(plain_vectors, PlainVector(data[1+i*row_length:(i+1)*row_length], context))
    end
    PlainMatrix(plain_vectors, length(plain_vectors), context)
end

function level(v::Union{SecureMatrix{<:Unencrypted}, PlainMatrix{<:Unencrypted}})
    0
end

function encrypt_impl(plain_matrix::PlainMatrix{<:Unencrypted}, public_key::PublicKey)
    SecureMatrix(plain_matrix.data, length(plain_matrix), plain_vector.context)
end

function decrypt_impl(secure_matrix::SecureMatrix{<:Unencrypted}, private_key::PrivateKey)
    plain_matrix = PlainVector(decrypt.(secure_matrix.data, private_key), length(secure_matrix),
                               secure_matrix.context)

    plain_matrix
end

bootstrap!(secure_matrix::SecureMatrix{<:Unencrypted}) = secure_matrix