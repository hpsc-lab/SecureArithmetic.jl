struct Unencrypted <: AbstractCryptoBackend
    # No data fields required
end

function generate_keys(context::SecureContext{<:Unencrypted})
    PublicKey(context, nothing), PrivateKey(context, nothing)
end

init_multiplication(context::SecureContext{<:Unencrypted}, private_key) = nothing
init_rotation(context::SecureContext{<:Unencrypted}, private_key, shifts) = nothing
init_bootstrapping(context::SecureContext{<:Unencrypted}, private_key) = nothing

function PlainVector(context::SecureContext{<:Unencrypted}, data::Vector{<:Real})
    plain_vector = PlainVector(data, context)
end

function encrypt(context::SecureContext{<:Unencrypted}, public_key, data::Vector{<:Real})
    SecureVector(data, context)
end

function encrypt(context::SecureContext{<:Unencrypted}, public_key,
                 plain_vector::PlainVector)
    SecureVector(plain_vector.plaintext, context)
end

function decrypt!(plain_vector, context::SecureContext{<:Unencrypted}, private_key,
                  secure_vector)
    plain_vector.plaintext .= secure_vector.ciphertext

    plain_vector
end

bootstrap!(context::SecureContext{<:Unencrypted}, secure_vector) = secure_vector

function decrypt(context::SecureContext{<:Unencrypted}, private_key, secure_vector)
    plain_vector = PlainVector(similar(secure_vector.ciphertext), context)

    decrypt!(plain_vector, context, private_key, secure_vector)
end

function add(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .+ sv2.ciphertext, sv1.context)
end

function subtract(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .- sv2.ciphertext, sv1.context)
end

function multiply(sv1::SecureVector{<:Unencrypted}, sv2::SecureVector{<:Unencrypted})
    SecureVector(sv1.ciphertext .* sv2.ciphertext, sv1.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, pv::PlainVector{<:Unencrypted})
    SecureVector(sv.ciphertext .* pv.plaintext, sv.context)
end

function multiply(sv::SecureVector{<:Unencrypted}, scalar::Real)
    SecureVector(sv.ciphertext .* scalar, sv.context)
end

function rotate(sv::SecureVector{<:Unencrypted}, shift)
    SecureVector(circshift(sv.ciphertext, shift), sv.context)
end
