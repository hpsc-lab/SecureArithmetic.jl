struct OpenFHEBackend{CryptoContextT} <: AbstractCryptoBackend
    crypto_context::CryptoContextT
end

function get_crypto_context(context::SecureContext{<:OpenFHEBackend})
    context.backend.crypto_context
end
function get_crypto_context(secure_vector::SecureVector{<:OpenFHEBackend})
    get_crypto_context(secure_vector.context)
end
function get_crypto_context(plain_vector::PlainVector{<:OpenFHEBackend})
    get_crypto_context(plain_vector.context)
end

function generate_keys(context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    keys = OpenFHE.KeyGen(cc)
    public_key = PublicKey(context, OpenFHE.public_key(keys))
    private_key = PrivateKey(context, OpenFHE.private_key(keys))

    public_key, private_key
end

function init_multiplication(context::SecureContext{<:OpenFHEBackend}, private_key)
    cc = get_crypto_context(context)
    OpenFHE.EvalMultKeyGen(cc, private_key.private_key)

    nothing
end

function init_rotation(context::SecureContext{<:OpenFHEBackend}, private_key, shifts)
    cc = get_crypto_context(context)
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, shifts)

    nothing
end

function init_bootstrapping(context::SecureContext{<:OpenFHEBackend}, private_key)
    cc = get_crypto_context(context)
    ring_dimension = OpenFHE.GetRingDimension(cc)
    num_slots = div(ring_dimension,  2)
    OpenFHE.EvalBootstrapKeyGen(cc, private_key.private_key, num_slots)

    nothing
end

function PlainVector(context::SecureContext{<:OpenFHEBackend}, data::Vector{<:Real})
    cc = get_crypto_context(context)
    plaintext = OpenFHE.MakeCKKSPackedPlaintext(cc, data)
    plain_vector = PlainVector(plaintext, context)

    plain_vector
end

function encrypt(context::SecureContext{<:OpenFHEBackend}, public_key, data::Vector{<:Real})
    plain_vector = PlainVector(context, data)
    secure_vector = encrypt(context, public_key, plain_vector)

    secure_vector
end

function encrypt(context::SecureContext{<:OpenFHEBackend}, public_key,
                 plain_vector::PlainVector)
    cc = get_crypto_context(context)
    ciphertext = OpenFHE.Encrypt(cc, public_key.public_key, plain_vector.plaintext)
    secure_vector = SecureVector(ciphertext, context)

    secure_vector
end

function decrypt!(plain_vector, context::SecureContext{<:OpenFHEBackend}, private_key,
                  secure_vector)
    cc = get_crypto_context(context)
    OpenFHE.Decrypt(cc, private_key.private_key, secure_vector.ciphertext,
                    plain_vector.plaintext)

    plain_vector
end

function decrypt(context::SecureContext{<:OpenFHEBackend}, private_key, secure_vector)
    plain_vector = PlainVector(OpenFHE.Plaintext(), context)

    decrypt!(plain_vector, context, private_key, secure_vector)
end


function bootstrap!(context::SecureContext{<:OpenFHEBackend}, secure_vector)
    cc = get_crypto_context(context)
    OpenFHE.EvalBootstrap(cc, secure_vector.ciphertext)

    secure_vector
end
function bootstrap!(context::SecureContext{<:OpenFHEBackend}, secure_vector)
    cc = get_crypto_context(context)
    OpenFHE.EvalBootstrap(cc, secure_vector.ciphertext)

    secure_vector
end

function add(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalAdd(cc, sv1.ciphertext, sv2.ciphertext)
    secure_vector = SecureVector(ciphertext, sv1.context)

    secure_vector
end

function subtract(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalSub(cc, sv1.ciphertext, sv2.ciphertext)
    secure_vector = SecureVector(ciphertext, sv1.context)

    secure_vector
end

function multiply(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalMult(cc, sv1.ciphertext, sv2.ciphertext)
    secure_vector = SecureVector(ciphertext, sv1.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.ciphertext, pv.plaintext)
    secure_vector = SecureVector(ciphertext, sv.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.ciphertext, scalar)
    secure_vector = SecureVector(ciphertext, sv.context)

    secure_vector
end

function rotate(sv::SecureVector{<:OpenFHEBackend}, shift)
    cc = get_crypto_context(sv)
    # We use `-shift` to match Julia's usual `circshift` direction
    ciphertext = OpenFHE.EvalRotate(cc, sv.ciphertext, -shift)
    secure_vector = SecureVector(ciphertext, sv.context)

    secure_vector
end
