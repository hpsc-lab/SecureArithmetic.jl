struct OpenFHEBackend{CryptoContextT} <: AbstractCryptoBackend
    crypto_context::CryptoContextT
end

function get_crypto_context(context::SecureContext{<:OpenFHEBackend})
    context.backend.crypto_context
end
function get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},
                                     PlainVector{<:OpenFHEBackend}})
    get_crypto_context(v.context)
end

function generate_keys(context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    keys = OpenFHE.KeyGen(cc)
    public_key = PublicKey(context, OpenFHE.public_key(keys))
    private_key = PrivateKey(context, OpenFHE.private_key(keys))

    public_key, private_key
end

function init_multiplication!(context::SecureContext{<:OpenFHEBackend},
                              private_key::PrivateKey)
    cc = get_crypto_context(context)
    OpenFHE.EvalMultKeyGen(cc, private_key.private_key)

    nothing
end

function init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                        shifts)
    cc = get_crypto_context(context)
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, shifts)

    nothing
end

function init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},
                             private_key::PrivateKey)
    cc = get_crypto_context(context)
    ring_dimension = OpenFHE.GetRingDimension(cc)
    num_slots = div(ring_dimension,  2)
    OpenFHE.EvalBootstrapKeyGen(cc, private_key.private_key, num_slots)

    nothing
end

function PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    plaintext = OpenFHE.MakeCKKSPackedPlaintext(cc, data)
    plain_vector = PlainVector(plaintext, length(data), context)

    plain_vector
end

function Base.show(io::IO, v::PlainVector{<:OpenFHEBackend})
    print(io, OpenFHE.GetRealPackedValue(v.data))
end

function Base.show(io::IO, ::MIME"text/plain", v::PlainVector{<:OpenFHEBackend})
    print(io, v.length, "-element PlainVector{OpenFHEBackend}:\n")
    Base.print_matrix(io, OpenFHE.GetRealPackedValue(v.data))
end

function encrypt(data::Vector{<:Real}, public_key, context::SecureContext{<:OpenFHEBackend})
    plain_vector = PlainVector(data, context)
    secure_vector = encrypt(plain_vector, public_key)

    secure_vector
end

function encrypt(plain_vector::PlainVector{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_vector.context
    cc = get_crypto_context(context)
    ciphertext = OpenFHE.Encrypt(cc, public_key.public_key, plain_vector.data)
    secure_vector = SecureVector(ciphertext, length(plain_vector), context)

    secure_vector
end

function decrypt!(plain_vector::PlainVector{<:OpenFHEBackend},
                  secure_vector::SecureVector{<:OpenFHEBackend}, private_key::PrivateKey)
    cc = get_crypto_context(secure_vector)
    OpenFHE.Decrypt(cc, private_key.private_key, secure_vector.data,
                    plain_vector.data)

    plain_vector
end

function decrypt(secure_vector::SecureVector{<:OpenFHEBackend}, private_key::PrivateKey)
    context = secure_vector.context
    plain_vector = PlainVector(OpenFHE.Plaintext(), length(secure_vector), context)

    decrypt!(plain_vector, secure_vector, private_key)
end


function bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend})
    context = secure_vector.context
    cc = get_crypto_context(context)
    OpenFHE.EvalBootstrap(cc, secure_vector.data)

    secure_vector
end


############################################################################################
# Arithmetic operations
############################################################################################

function add(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalAdd(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), sv1.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function subtract(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalSub(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), sv1.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function subtract(pv::PlainVector{<:OpenFHEBackend}, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, pv.data, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function subtract(scalar::Real, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, scalar, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function negate(sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalNegate(cc, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function multiply(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalMult(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), sv1.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end

function rotate(sv::SecureVector{<:OpenFHEBackend}, shift)
    cc = get_crypto_context(sv)
    # We use `-shift` to match Julia's usual `circshift` direction
    ciphertext = OpenFHE.EvalRotate(cc, sv.data, -shift)
    secure_vector = SecureVector(ciphertext, length(sv), sv.context)

    secure_vector
end
