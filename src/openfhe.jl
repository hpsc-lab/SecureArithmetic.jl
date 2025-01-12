"""
    OpenFHEBackend

Cryptography backend for use with the homomorphic encryption library OpenFHE
(https://github.com/openfheorg/openfhe-development).

See also: [`SecureContext`](@ref), [`Unencrypted`](@ref)
"""
struct OpenFHEBackend{CryptoContextT} <: AbstractCryptoBackend
    crypto_context::CryptoContextT
end

"""
    get_crypto_context(context::SecureContext{<:OpenFHEBackend})

Return a `OpenFHE.CryptoContext` object stored in a given `context`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref)
"""
function get_crypto_context(context::SecureContext{<:OpenFHEBackend})
    context.backend.crypto_context
end
"""
    get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},
                                PlainVector{<:OpenFHEBackend},
                                SecureMatrix{<:OpenFHEBackend},
                                PlainMatrix{<:OpenFHEBackend}})

Return a `OpenFHE.CryptoContext` object stored in `v`.

See also: [`SecureContext`](@ref), [`SecureVector`](@ref), [`PlainVector`](@ref),
[`OpenFHEBackend`](@ref)
"""
function get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},
                                     PlainVector{<:OpenFHEBackend},
                                     SecureMatrix{<:OpenFHEBackend},
                                     PlainMatrix{<:OpenFHEBackend},
                                     SecureArray{<:OpenFHEBackend},
                                     PlainArray{<:OpenFHEBackend}})
    get_crypto_context(v.context)
end

"""
    generate_keys(context::SecureContext{<:OpenFHEBackend})

Generate and return public and private keys.

See also: [`PublicKey`](@ref), [`PrivateKey`](@ref), [`SecureContext`](@ref),
[`OpenFHEBackend`](@ref)
"""
function generate_keys(context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    keys = OpenFHE.KeyGen(cc)
    public_key = PublicKey(context, OpenFHE.public_key(keys))
    private_key = PrivateKey(context, OpenFHE.private_key(keys))

    public_key, private_key
end

"""
    init_multiplication!(context::SecureContext{<:OpenFHEBackend},
                         private_key::PrivateKey)

Generate relinearization key for use with `OpenFHE.EvalMult` using the `private_key`, and
store it in the given `context`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref)
"""
function init_multiplication!(context::SecureContext{<:OpenFHEBackend},
                              private_key::PrivateKey)
    cc = get_crypto_context(context)
    OpenFHE.EvalMultKeyGen(cc, private_key.private_key)

    nothing
end

"""
    init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                   shifts)

Generate rotation keys for use with `OpenFHE.EvalRotate` using the `private_key` and for the
rotation indexes in `shifts`. The keys are stored in the given `context`.
Positive shift defines rotation to the right, e.g. a rotation with a shift 1:
[1, 2, 3, 4] -> [4, 1, 2, 3].
Negative shift defines rotation to the left, e.g. a rotation with a shift -1:
[1, 2, 3, 4] -> [2, 3, 4, 1].

Note: Here, indexes stored in `shifts` have reversed sign compared to rotation indexes used in
OpenFHE.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref)
"""
function init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                        shifts)
    cc = get_crypto_context(context)
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -shifts)

    nothing
end

"""
    init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},
                        private_key::PrivateKey)

Generate the necessary keys from `private_key` to enable bootstrapping for a given
`context`. Supported for CKKS only.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref),
[`bootstrap!`](@ref)
"""
function init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},
                             private_key::PrivateKey)
    cc = get_crypto_context(context)
    encoding_parameters = OpenFHE.GetEncodingParams(cc)
    slots = OpenFHE.GetBatchSize(encoding_parameters)
    OpenFHE.EvalBootstrapKeyGen(cc, private_key.private_key, slots)

    nothing
end

"""
    PlainVector(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainVector`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainVector(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend})
    cc = get_crypto_context(context)
    plaintext = OpenFHE.MakeCKKSPackedPlaintext(cc, data)
    capacity = OpenFHE.GetSlots(plaintext)
    plain_vector = PlainVector(plaintext, length(data), capacity, context)

    plain_vector
end

"""
    PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainVector`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).
    
See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainVector(convert(Vector{Float64}, data), context)
end

function Base.show(io::IO, v::PlainVector{<:OpenFHEBackend})
    print(io, collect(v))
end

function Base.show(io::IO, ::MIME"text/plain", v::PlainVector{<:OpenFHEBackend})
    print(io, v.length, "-element PlainVector{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(v))
end

"""
    collect(v::PlainVector{<:OpenFHEBackend})

Decode and return the real-valued data contained in `v`.

See also: [`PlainVector`](@ref), [`OpenFHEBackend`](@ref)
"""
function Base.collect(v::PlainVector{<:OpenFHEBackend})
    collect(OpenFHE.GetRealPackedValue(v.data)[1:v.length])
end

"""
    level(v::Union{SecureVector{<:OpenFHEBackend}, PlainVector{<:OpenFHEBackend}})

Return the number of scalings, referred to as the level, performed over `v`.

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`OpenFHEBackend`](@ref)
"""
function level(v::Union{SecureVector{<:OpenFHEBackend}, PlainVector{<:OpenFHEBackend}})
    Int(OpenFHE.GetLevel(v.data))
end

function encrypt_impl(data::Vector{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:OpenFHEBackend})
    plain_vector = PlainVector(data, context)
    secure_vector = encrypt(plain_vector, public_key)

    secure_vector
end

function encrypt_impl(plain_vector::PlainVector{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_vector.context
    cc = get_crypto_context(context)
    ciphertext = OpenFHE.Encrypt(cc, public_key.public_key, plain_vector.data)
    capacity = OpenFHE.GetSlots(ciphertext)
    secure_vector = SecureVector(ciphertext, length(plain_vector), capacity, context)

    secure_vector
end

function decrypt_impl!(plain_vector::PlainVector{<:OpenFHEBackend},
                       secure_vector::SecureVector{<:OpenFHEBackend},
                       private_key::PrivateKey)
    cc = get_crypto_context(secure_vector)
    OpenFHE.Decrypt(cc, private_key.private_key, secure_vector.data,
                    plain_vector.data)

    plain_vector
end

function decrypt_impl(secure_vector::SecureVector{<:OpenFHEBackend},
                      private_key::PrivateKey)
    context = secure_vector.context
    plain_vector = PlainVector(OpenFHE.Plaintext(), length(secure_vector),
                               capacity(secure_vector), context)

    decrypt!(plain_vector, secure_vector, private_key)
end

"""
    bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend}, num_iterations = 1,
               precision = 0)
     
Refresh a given `secure_vector` to increase the multiplication depth. Supported for CKKS only.
Please refer to the OpenFHE documentation for details on the arguments `num_iterations` and
`precision`.

See also: [`SecureVector`](@ref), [`OpenFHEBackend`](@ref), [`init_bootstrapping!`](@ref)
"""
function bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend}, num_iterations = 1,
                    precision = 0)
    context = secure_vector.context
    cc = get_crypto_context(context)
    secure_vector.data = OpenFHE.EvalBootstrap(cc, secure_vector.data, num_iterations, precision)

    secure_vector
end


############################################################################################
# Arithmetic operations
############################################################################################

function add(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalAdd(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function add(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalAdd(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalSub(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(pv::PlainVector{<:OpenFHEBackend}, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, pv.data, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function subtract(scalar::Real, sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalSub(cc, scalar, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function negate(sv::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalNegate(cc, sv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function multiply(sv1::SecureVector{<:OpenFHEBackend}, sv2::SecureVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv1)
    ciphertext = OpenFHE.EvalMult(cc, sv1.data, sv2.data)
    secure_vector = SecureVector(ciphertext, length(sv1), capacity(sv1), sv1.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, pv::PlainVector{<:OpenFHEBackend})
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, pv.data)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function multiply(sv::SecureVector{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sv)
    ciphertext = OpenFHE.EvalMult(cc, sv.data, scalar)
    secure_vector = SecureVector(ciphertext, length(sv), capacity(sv), sv.context)

    secure_vector
end

function rotate(sv::SecureVector{<:OpenFHEBackend}, shift; wrap_by)
    cc = get_crypto_context(sv)

    # We use `-shift` to match Julia's usual `circshift` direction
    ciphertext_rotated = OpenFHE.EvalRotate(cc, sv.data, -shift)

    if wrap_by == :length && length(sv) < capacity(sv)
        # Mask rotated ciphertext
        mask_rotated = zeros(capacity(sv))
        if shift < 0
            first = 1
            last = length(sv) - abs(shift)
            mask_rotated[first:last] .= 1
        else
            first = abs(shift) + 1
            last = length(sv)
            mask_rotated[first:last] .= 1
        end
        plaintext1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask_rotated)
        ciphertext1 = OpenFHE.EvalMult(cc, ciphertext_rotated, plaintext1)

        # Compute remaining part of the ciphertext
        shift_rest = -sign(shift) * (length(sv) - abs(shift))
        ciphertext_rest = OpenFHE.EvalRotate(cc, sv.data, -shift_rest)

        # Mask remaining part of the ciphertext
        mask_rest = zeros(capacity(sv))
        if shift < 0
            first = length(sv) - abs(shift) + 1
            last = length(sv)
            mask_rest[first:last] .= 1
        else
            first = 1
            last = abs(shift)
            mask_rest[first:last] .= 1
        end
        plaintext2 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask_rest)
        ciphertext2 = OpenFHE.EvalMult(cc, ciphertext_rest, plaintext2)

        ciphertext_final = OpenFHE.EvalAdd(cc, ciphertext1, ciphertext2)
        secure_vector = SecureVector(ciphertext_final, length(sv), capacity(sv),
                                     sv.context)
    else
        # If wrapping by capacity is requested and length is less than capacity
        secure_vector = SecureVector(ciphertext_rotated, length(sv), capacity(sv),
                                     sv.context)
    end

    secure_vector
end


############################################################################################
# Matrix
############################################################################################

"""
    init_matrix_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                          shifts, shape)

Generate rotation keys for matrix rotation with `OpenFHE.EvalRotate` using the `private_key` and for the
rotation indexes in `shifts`.
`shifts` is a pair of integers given as a tuple, or a list of tuples of integers.
The keys are stored in the given
`context`. A positive shift defines a rotation to the right/bottom, e.g., a rotation with shift `(1, 0)`:
[1 2 3; 4 5 6; 7 8 9] -> [7 8 9; 1 2 3; 4 5 6].
Negative shifts define rotation to the left/top, e.g., a rotation with a shift `(0, -1)`:
[1 2 3; 4 5 6; 7 8 9] -> [3 1 2; 6 4 5; 9 7 8].
"""
function init_matrix_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                               shifts, shape)
    cc = get_crypto_context(context)
    shifts_ = []
    nrows, ncols = shape
    for (shift_row, shift_col) in shifts
        # minimum required shift
        shift_row %= nrows
        shift_col %= ncols
        # appropriate shift for matrix packed in vector
        shift = []
        if shift_row == 0 && shift_col != 0
            # Since the matrix is saved in a vector in column-major order, only one rotation is
            # required for column shifting. 
            shift = [shift_col*nrows]
        else
            # In the general case, in addition to column shifting, a shift within each column is
            # required. Since this shift inside a column must be circular, two rotations
            # must be performed (similar to the circshift for SecureVector).
            shift = [shift_row+shift_col*nrows, -sign(shift_row)*(nrows-abs(shift_row))+shift_col*nrows]
        end
        append!(shifts_, shift)
        # additional shift required in case of rotation in shift_col direction
        if shift_col != 0
            # Circularity of rotation within a single column was already ensured. The following
            # shift is necessary to maintain the circularity of column shifting, see circshift for
            # SecureVector.
            shift_rest = -sign.(shift) .* (nrows*ncols .- abs.(shift))
            append!(shifts_, shift_rest)
        end
    end
    # All shifts stored in shifts_ correspond to Base.circshift, but to use with OpenFHE, all shifts
    # have to be negated.
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -shifts_)

    nothing
end
function init_matrix_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                               shift::Tuple{<:Integer, <:Integer}, shape)
    init_matrix_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key, [shift], shape)
end

function PlainMatrix(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend},
                     shape::Tuple{Int, Int})
    cc = get_crypto_context(context)
    plaintext = OpenFHE.MakeCKKSPackedPlaintext(cc, data)
    capacity = OpenFHE.GetSlots(plaintext)
    plain_matrix = PlainMatrix(plaintext, shape, capacity, context)

    plain_matrix
end

function PlainMatrix(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend},
                     shape::Tuple{Int, Int})
    PlainMatrix(Vector{Float64}(data), context, shape)
end

function PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainMatrix(Vector{Float64}(vec(data)), context, size(data))
end

function Base.show(io::IO, m::PlainMatrix{<:OpenFHEBackend})
    print(io, collect(m))
end

function Base.show(io::IO, ::MIME"text/plain", m::PlainMatrix{<:OpenFHEBackend})
    print(io, m.shape, "-shaped PlainMatrix{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(m))
end

function Base.collect(plain_matrix::PlainMatrix{<:OpenFHEBackend})
    data = OpenFHE.GetRealPackedValue(plain_matrix.data)[1:length(plain_matrix)]
    Matrix{Float64}(reshape(data, plain_matrix.shape))
end

function level(m::Union{SecureMatrix{<:OpenFHEBackend}, PlainMatrix{<:OpenFHEBackend}})
    Int(OpenFHE.GetLevel(m.data))
end

function encrypt_impl(data::Matrix{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:OpenFHEBackend})
    plain_matrix = PlainMatrix(data, context)
    secure_matrix = encrypt(plain_matrix, public_key)

    secure_matrix
end

function encrypt_impl(plain_matrix::PlainMatrix{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_matrix.context
    cc = get_crypto_context(context)
    ciphertext = OpenFHE.Encrypt(cc, public_key.public_key, plain_matrix.data)
    capacity = OpenFHE.GetSlots(ciphertext)
    secure_matrix = SecureMatrix(ciphertext, plain_matrix.shape, capacity, context)

    secure_matrix
end

function decrypt_impl!(plain_matrix::PlainMatrix{<:OpenFHEBackend},
                       secure_matrix::SecureMatrix{<:OpenFHEBackend},
                       private_key::PrivateKey)
    cc = get_crypto_context(secure_matrix)
    OpenFHE.Decrypt(cc, private_key.private_key, secure_matrix.data,
                    plain_matrix.data)

    plain_matrix
end

function decrypt_impl(secure_matrix::SecureMatrix{<:OpenFHEBackend},
                      private_key::PrivateKey)
    context = secure_matrix.context
    plain_matrix = PlainMatrix(OpenFHE.Plaintext(), size(secure_matrix),
                               capacity(secure_matrix), context)

    decrypt!(plain_matrix, secure_matrix, private_key)
end

function bootstrap!(secure_matrix::SecureMatrix{<:OpenFHEBackend})
    context = secure_matrix.context
    cc = get_crypto_context(context)
    secure_matrix.data = OpenFHE.EvalBootstrap(cc, secure_matrix.data)

    secure_matrix
end


############################################################################################
# Arithmetic operations
############################################################################################

function add(sm1::SecureMatrix{<:OpenFHEBackend}, sm2::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm1)
    ciphertext = OpenFHE.EvalAdd(cc, sm1.data, sm2.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm1), capacity(sm1), sm1.context)

    secure_matrix
end

function add(sm::SecureMatrix{<:OpenFHEBackend}, pm::PlainMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalAdd(cc, sm.data, pm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function add(sm::SecureMatrix{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalAdd(cc, sm.data, scalar)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function subtract(sm1::SecureMatrix{<:OpenFHEBackend}, sm2::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm1)
    ciphertext = OpenFHE.EvalSub(cc, sm1.data, sm2.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm1), capacity(sm1), sm1.context)

    secure_matrix
end

function subtract(sm::SecureMatrix{<:OpenFHEBackend}, pm::PlainMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalSub(cc, sm.data, pm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function subtract(pm::PlainMatrix{<:OpenFHEBackend}, sm::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalSub(cc, pm.data, sm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function subtract(sm::SecureMatrix{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalSub(cc, sm.data, scalar)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function subtract(scalar::Real, sm::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalSub(cc, scalar, sm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function negate(sm::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalNegate(cc, sm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function multiply(sm1::SecureMatrix{<:OpenFHEBackend}, sm2::SecureMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm1)
    ciphertext = OpenFHE.EvalMult(cc, sm1.data, sm2.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm1), capacity(sm1), sm1.context)

    secure_matrix
end

function multiply(sm::SecureMatrix{<:OpenFHEBackend}, pm::PlainMatrix{<:OpenFHEBackend})
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalMult(cc, sm.data, pm.data)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function multiply(sm::SecureMatrix{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sm)
    ciphertext = OpenFHE.EvalMult(cc, sm.data, scalar)
    secure_matrix = SecureMatrix(ciphertext, size(sm), capacity(sm), sm.context)

    secure_matrix
end

function rotate(sm::SecureMatrix{<:OpenFHEBackend}, shift)
    # operate with data stored in matrix in form of vector
    sv = SecureVector(sm.data, length(sm), sm.capacity, sm.context)
    # minimum required shift
    shift = shift .% size(sm)
    shift_row, shift_col = shift
    nrows, ncols = size(sm)
    # split algorithm in several cases depending on shift
    if shift_row == 0
        shift_main = shift_col*nrows
        sv = circshift(sv, shift_main; wrap_by=:length)
    else
        # mask for main part of single column
        mask_part = zeros(nrows)
        if shift_row > 0
            first = 1
            last = nrows - shift_row
            mask_part[first:last] .= 1
        else
            first = -shift_row + 1
            mask_part[first:end] .= 1
        end
        # repeat mask for each column
        mask = repeat(mask_part, outer=ncols)
        plaintext1 = PlainVector(mask, sm.context)
        # shift for main part
        shift_main = shift_row + shift_col * nrows

        # mask for rest part of single column
        mask_part_rest = zeros(nrows)
        if shift_row > 0
            first = nrows - shift_row + 1
            mask_part_rest[first:end] .= 1
        else
            first = 1
            last = -shift_row
            mask_part_rest[first:last] .= 1
        end
        # repeat mask for each column
        mask_rest = repeat(mask_part_rest, outer=ncols)
        plaintext2 = PlainVector(mask_rest, sm.context)
        # shift for rest part
        shift_rest = -sign(shift_row)*(nrows - abs(shift_row)) + shift_col * nrows

        # If shift_col == 0, it is sufficient to use wrap_by=:capacity to utilize lower
        # multiplicative depth.
        if shift_col == 0
            sv = circshift(sv*plaintext1, shift_main; wrap_by=:capacity) +
                 circshift(sv*plaintext2, shift_rest; wrap_by=:capacity)
        else
            sv = circshift(sv*plaintext1, shift_main; wrap_by=:length) +
                 circshift(sv*plaintext2, shift_rest; wrap_by=:length)
        end
    end

    SecureMatrix(sv.data, size(sm), capacity(sm), sm.context)
end


############################################################################################
# Array
############################################################################################

function init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                              shift::Union{Integer, Tuple}, shape)
    init_array_rotation!(context, private_key, [shift], shape)
end
function init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                              shifts, shape)
    cc = get_crypto_context(context)
    # Get shifts for precompilation
    shifts_ = get_shifts_array(context, private_key, shifts, shape)
    # All shifts stored in shifts_ correspond to Base.circshift, but to use with OpenFHE, all shifts
    # have to be negated.
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -unique(shifts_))

    nothing
end

function get_shifts_array(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                          shifts::Vector{<:Integer}, shape)
    # extract capacity
    cc = get_crypto_context(context)
    capacity = OpenFHE.GetBatchSize(OpenFHE.GetEncodingParams(cc))
    # length of an array
    array_length = prod(shape)
    # length of short array
    short_length = array_length % capacity
    # empty places in short array
    empty_places = capacity - short_length
    # number of ciphertexts in array
    n_ciphertexts = Int(ceil(array_length/capacity))
    # minimal required shift
    shifts = shifts .% array_length
    # store all openfhe shifts to enable
    shifts_ = []
    # iterate over all shifts
    for i in range(1, length(shifts))
        # convert negative shift to positiv one
        if shifts[i] < 0
            shifts[i] = array_length + shifts[i]
        end
        # add all shifts from implementation of rotate function
        shifts[i] += empty_places
        shift1 = div(shifts[i], capacity)
        shift2 = shifts[i] - capacity * shift1
        push!(shifts_, shift2)
        if empty_places != 0
            push!(shifts_, short_length)
            if shift1 % n_ciphertexts == 0
                push!(shifts_, shift2 - empty_places)
            else
                push!(shifts_, shift2 + short_length)
            end
        end
    end

    shifts_
end

function PlainArray(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend}, 
                    shape::Tuple)
    cc = get_crypto_context(context)
    capacity = OpenFHE.GetBatchSize(OpenFHE.GetEncodingParams(cc))
    n_vectors = ceil(Int, length(data)/capacity)
    plaintexts = OpenFHE.Plaintext[]
    lengths = Int[]
    for i in range(1, n_vectors)
        start = (i-1)*capacity + 1
        stop = min(i*capacity, length(data))
        push!(plaintexts, OpenFHE.MakeCKKSPackedPlaintext(cc, data[start:stop]))
        push!(lengths, stop - start + 1)
    end
    capacities = OpenFHE.GetSlots.(plaintexts)
    plain_array = PlainArray(plaintexts, shape, lengths, capacities, context)

    plain_array
end

function PlainArray(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend},
                    shape::Tuple)
    PlainArray(Vector{Float64}(data), context, shape)
end

function PlainArray(data::Array{Float64}, context::SecureContext{<:OpenFHEBackend})
    PlainArray(Vector{Float64}(vec(data)), context, size(data))
end

function Base.show(io::IO, m::PlainArray{<:OpenFHEBackend})
    print(io, collect(m))
end

function Base.show(io::IO, ::MIME"text/plain", m::PlainArray{<:OpenFHEBackend})
    print(io, m.shape, "-shaped PlainArray{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(m))
end

function Base.collect(plain_array::PlainArray{<:OpenFHEBackend})
    data = Vector.(OpenFHE.GetRealPackedValue.(plain_array.data))
    keepat!.(data, range.(1, plain_array.lengths))
    data = reduce(vcat, data)

    Array{Float64, length(plain_array.shape)}(reshape(data, plain_array.shape))
end

function level(m::Union{SecureArray{<:OpenFHEBackend}, PlainArray{<:OpenFHEBackend}})
    Int.(OpenFHE.GetLevel.(m.data))
end

# function is not unique for data::Vector ot data::Matrix
#=function encrypt_impl(data::Array{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:OpenFHEBackend})
    plain_array = PlainArray(data, context)
    secure_array = encrypt(plain_array, public_key)

    secure_array
end=#

function encrypt_impl(plain_array::PlainArray{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_array.context
    cc = get_crypto_context(context)
    ciphertexts = OpenFHE.Ciphertext[]
    for pv in plain_array.data
        push!(ciphertexts, OpenFHE.Encrypt(cc, public_key.public_key, pv))
    end
    capacities = OpenFHE.GetSlots.(ciphertexts)
    secure_array = SecureArray(ciphertexts, plain_array.shape, plain_array.lengths,
                               capacities, context)

    secure_array
end

function decrypt_impl!(plain_array::PlainArray{<:OpenFHEBackend},
                       secure_array::SecureArray{<:OpenFHEBackend},
                       private_key::PrivateKey)
    cc = get_crypto_context(secure_array)
    for i in range(1, length(secure_array.data))
        OpenFHE.Decrypt(cc, private_key.private_key, secure_array.data[i],
                        plain_array.data[i])
    end

    plain_array
end

function decrypt_impl(secure_array::SecureArray{<:OpenFHEBackend},
                      private_key::PrivateKey)
    context = secure_array.context
    plaintexts = Vector{OpenFHE.Plaintext}(undef, length(secure_array.data))
    for i in range(1, length(plaintexts))
        plaintexts[i] = OpenFHE.Plaintext()
    end
    plain_array = PlainArray(plaintexts, size(secure_array), secure_array.lengths, 
                             secure_array.capacities, context)

    decrypt!(plain_array, secure_array, private_key)
end

function bootstrap!(secure_array::SecureArray{<:OpenFHEBackend})
    context = secure_array.context
    cc = get_crypto_context(context)
    Threads.@threads for i in range(1, length(secure_array.data))
        secure_array.data[i] = OpenFHE.EvalBootstrap(cc, secure_array.data[i])
    end

    secure_array
end


############################################################################################
# Arithmetic operations
############################################################################################
# TODO: Multithreading in each operation for SecureArray

function add(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(pa::PlainArray{<:OpenFHEBackend}, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, pa.data[i], sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(scalar::Real, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, scalar, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function negate(sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalNegate(cc, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function multiply(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function rotate(sa::SecureArray{<:OpenFHEBackend, 1}, shift::Integer)
    # minimal required shift
    shift = shift % length(sa)
    # convert negative shift to positiv one
    if shift < 0
        shift = length(sa) + shift
    end
    # operate with data stored in many secure vectors
    sv = Vector{SecureVector}(undef, length(sa.data))
    for i in range(1, length(sa.data))
        sv[i] = SecureVector(sa.data[i], sa.lengths[i], sa.capacities[i], sa.context)
    end
    # only the last vector can be smaller than capacity, export capacity and length
    vec_capacity = capacity(sv[end])
    short_length = length(sv[end])
    empty_places = vec_capacity - short_length
    # update required shift with respect of empty places in last vector
    shift += empty_places
    # shift secure vectors, so that shift is only required in each secure vector
    # and between direct neighbours
    shift1 = div(shift, vec_capacity)
    sv = circshift(sv, shift1)
    # shift for individual vectors
    shift2 = shift - vec_capacity * shift1
    # if the last vector is also full, rotation is simplier
    if empty_places == 0
        # shift each vector
        sv = circshift.(sv, shift2, wrap_by=:capacity)
        # first shift2 elements of each vector have to be moved 
        # to the first shift2 elements of next vector
        sv_new = Vector{SecureVector}(undef, length(sv))
        # mask for fist shift2 elements of each vector
        mask1 = zeros(vec_capacity)
        mask1[1:shift2] .= 1
        mask1 = PlainVector(mask1, sa.context)
        # mask for remaining part of each vector
        mask2 = zeros(vec_capacity)
        mask2[shift2+1:end] .= 1
        mask2 = PlainVector(mask2, sa.context)
        for i in range(1, length(sv))
            sv_new[i] = circshift(sv, 1)[i] * mask1 + sv[i] * mask2
        end
        sv = sv_new
    # next case when after rotating a whole array (not individual ciphertexts) 
    # short vector is already the last one 
    elseif shift1 % length(sv) == 0
        # if short vector is at the end, shift does not need to be corrected due to its empty places 
        # (except for the short vector), change the shift back
        shift2 -= empty_places
        # rotate all vectors except the last one
        sv[1:end-1] = circshift.(sv[1:end-1], shift2, wrap_by=:capacity)
        # rotate the last considering empty places
        sv[end] = circshift(sv[end], shift2 + empty_places, wrap_by=:capacity)
        # first shift2 elements of each vector have to be moved to the next one and rotate the last
        # vector additionally
        sv_new = Vector{SecureVector}(undef, length(sv))
        # mask for fist shift2 elements of each vector
        mask1 = zeros(vec_capacity)
        mask1[1:shift2] .= 1
        mask1 = PlainVector(mask1, sa.context)
        # mask for remaining part of each vector
        mask2 = zeros(vec_capacity)
        mask2[shift2+1:end] .= 1
        mask2 = PlainVector(mask2, sa.context)
        for i in range(1, length(sv)-1)
            sv_new[i] = circshift(sv, 1)[i] * mask1 + sv[i] * mask2
        end
        # The last vector have to be also additionally rotated by its length, so that elements stay
        # at correct position
        sv_new[end] = sv[end-1] * mask1 + circshift(sv[end], short_length, wrap_by=:capacity) * mask2
        sv = sv_new
    # The last case when short vector is not the last one and its empty places have to be filled,
    # so that the last vector still the only short one
    else
        # first shift1 vectors have to be rotated by shift2
        sv[1:shift1] = circshift.(sv[1:shift1], shift2, wrap_by=:capacity)
        # all other vectors except last one have to be rotated by shift2 + short_length to compensate
        # empty places in array's middle
        sv[shift1+1:end-1] = circshift.(sv[shift1+1:end-1], shift2 + short_length, wrap_by=:capacity)
        # the last one is also shifted by shift2
        sv[end] = circshift(sv[end], shift2, wrap_by=:capacity)
        # for all vectors before short first shift2 elements have to be moved from the previous vector
        sv_new = Vector{SecureVector}(undef, length(sv))
        # mask for fist shift2 elements of each vector
        mask1 = zeros(vec_capacity)
        mask1[1:shift2] .= 1
        mask1 = PlainVector(mask1, sa.context)
        # mask for remaining part of each vector
        mask2 = zeros(vec_capacity)
        mask2[shift2+1:end] .= 1
        mask2 = PlainVector(mask2, sa.context)
        for i in range(1, shift1-1)
            sv_new[i] = circshift(sv, 1)[i] * mask1 + sv[i] * mask2
        end
        # depending on how shift2 and short_length relate, several cases are possible
        if shift2 == empty_places
            # if after rotation last element of short vector is already on last place, it needs only first
            # shift2 elements from previous vector
            sv_new[shift1] = circshift(sv, 1)[shift1] * mask1 + sv[shift1] * mask2
            # due to emty place in new last vector, it has to be rotated
            sv_new[end] = circshift(sv[end], short_length)
            # all other vectors are without changes
            sv_new[shift1+1:end-1] = sv[shift1+1:end-1]
        # if last element of short vector after circular shift has come back at front, it has to be moved
        # to the next vector, as well as for all next vectors
        elseif shift2 > empty_places
            # move first shift2 elements to the short vector from previous
            sv_new[shift1] = circshift(sv, 1)[shift1] * mask1 + sv[shift1] * mask2
            # number of elements to shift from short vector to the next one
            n_shift = shift2 - empty_places
            # mask for first n_shift elements 
            mask3 = zeros(vec_capacity)
            mask3[1:n_shift] .= 1
            mask3 = PlainVector(mask3, sa.context)
            # mask for remaining part of each vector
            mask4 = zeros(vec_capacity)
            mask4[n_shift+1:end] .= 1
            mask4 = PlainVector(mask4, sa.context)
            # move n_shift elements starting from short vector upto last one
            for i in range(shift1+1, length(sv)-1)
                sv_new[i] = sv[i-1] * mask3 + sv[i] * mask4
            end
            # last one has to be additionally rotated due to empty place
            sv_new[end] = sv[end-1] * mask3 +
                          circshift(sv[end], short_length, wrap_by=:capacity) * mask4
        # if the last element of short vector didn't reach the end of vector, elements
        # from previous vector have to be moved to the end of short vector
        else
            # number of elements to shift from next vector
            n_shift = empty_places - shift2
            # mask for short_length elements after shift2 elements
            mask3 = zeros(vec_capacity)
            mask3[1+shift2:short_length+shift2] .= 1
            mask3 = PlainVector(mask3, sa.context)
            # mask for last n_shift elements
            mask4 = zeros(vec_capacity)
            mask4[end-n_shift+1:end] .= 1
            mask4 = PlainVector(mask4, sa.context)
            # mask for first capacity-n_shift elements
            mask5 = zeros(vec_capacity)
            mask5[1:end-n_shift] .= 1
            mask5 = PlainVector(mask5, sa.context)
            # short vector is a combination first shift2 elements of previous vector,
            # last n_shift elements of the next vector, and itself
            sv_new[shift1] = circshift(sv, 1)[shift1] * mask1 + sv[shift1] * mask3 +
                             circshift(sv, -1)[shift1] * mask4
            # All vectors after the short one upto prelast vector
            # become last n_shift elements from the next vector
            for i in range(shift1+1, length(sv)-2)
                sv_new[i] = sv[i+1] * mask4 + sv[i] * mask5
            end
            # last vector is rotated due to empty places
            sv_new[end] = circshift(sv[end], short_length, wrap_by=:capacity)
            # prelast becomes n_shift elements from the last vector
            # from positions shift2+1:shift2+n_shift
            sv_new[end-1] = sv_new[end] * mask4 + sv[end-1] * mask5
        end
        # update vector
        sv = sv_new
    end

    SecureArray(getproperty.(sv, :data), size(sa), sa.lengths, sa.capacities, sa.context)
end
