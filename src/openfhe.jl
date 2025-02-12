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
    get_crypto_context(a::Union{SecureArray{<:OpenFHEBackend},
                                PlainArray{<:OpenFHEBackend}})

Return a `OpenFHE.CryptoContext` object stored in `a`.

See also: [`SecureContext`](@ref), [`SecureArray`](@ref), [`PlainArray`](@ref),
[`OpenFHEBackend`](@ref)
"""
function get_crypto_context(a::Union{SecureArray{<:OpenFHEBackend},
                                     PlainArray{<:OpenFHEBackend}})
    get_crypto_context(a.context)
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
                   shape::Union{Integer, NTuple{N, Integer}}, shifts...)

Generate all required rotation keys for applying `shifts` with `circshift` for arrays of
the given `shape` using the `private_key`. The keys are stored in the given `context`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref)
"""
function init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                        shape::Union{Integer, NTuple{N, Integer}}, shifts...) where N
    cc = get_crypto_context(context)
    # Get rotation indices for precompilation
    rotation_indices = compute_rotation_indices_nd(context, shape, shifts)
    # All rotation indices correspond to Base.circshift, but to use with OpenFHE,
    # all rotation indices have to be negated.
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -unique(rotation_indices))

    nothing
end

# Computes rotation indices to enable 1D circshift
function compute_rotation_indices_1d(context, shape, shifts)
    # extract capacity
    cc = get_crypto_context(context)
    capacity = OpenFHE.GetBatchSize(OpenFHE.GetEncodingParams(cc))
    # length of an array
    array_length = prod(shape)
    # number of ciphertexts in array
    n_ciphertexts = Int(ceil(array_length/capacity))
    # empty places in short vector
    empty_places = capacity * n_ciphertexts - array_length
    # length of short vector
    short_length = capacity - empty_places
    # store all indices to enable
    indices = Int[]
    # iterate over all shifts
    for shift in shifts
        # add all required indices from implementation of rotate function
        shift += empty_places
        shift1 = div(shift, capacity)
        rotation_index = shift - capacity * shift1
        push!(indices, rotation_index)
        push!(indices, rotation_index - empty_places)
    end
    push!(indices, short_length)

    indices
end

# Computes rotation indices to enable nD circshift (n>1).
# Since nD circshift uses many 1D circshifts, this function 
# computes required 1D shifts and then call the function `compute_rotation_indices_1d `from above
# to translate them into OpenFHE rotation indices
function compute_rotation_indices_nd(context, shape, shifts)
    # dimensionality of arrays
    n = length(shape)
    # calculate length of each dimension
    lengths = ones(Int, n)
    for i in 2:n
        lengths[i] = prod(shape[1:i-1])
    end
    # assemble 1d shifts
    shifts_1d = Int[]
    for shift in shifts
        if length(shift) > n
            throw(ArgumentError("Got shift with length $(length(shift)), expected $n"))
        else
            # if shift is shorter than shape, fill it up with zeros
            shift = vcat(collect(shift), zeros(Integer, n - length(shift)))
        end
        # minimal required rotation
        shift = shift .% shape
        # convert negative shift to positive
        for i in 1:n
            if shift[i] < 0
                shift[i] = shape[i] + shift[i]
            end
        end
        # combination of all shifts (in each dimension) in 1D shift
        main_1d_shift = sum(shift .* lengths)
        push!(shifts_1d, main_1d_shift)
        # all possible combinations of dimensions (with non-zero shift)
        combinations = Vector{Int}[]
        for i in 1:n-1
            if shift[i] != 0
                append!(combinations, push!.(copy.(combinations), i))
                push!(combinations, [i])
            end
        end
        # shifts to retrieve cyclicity
        for i in combinations
            push!(shifts_1d, main_1d_shift)
            for j in i
                shifts_1d[end] -= lengths[j+1]
            end
        end
    end

    # compute rotation indices for 1D circshift
    compute_rotation_indices_1d(context, prod(shape), shifts_1d)
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
    PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainVector`](@ref) takes an unencrypted `data` vector and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainVector`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureVector`](@ref).

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainArray(data, context)
end

"""
    PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainMatrix`](@ref) takes an unencrypted `data` matrix and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainMatrix`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureMatrix`](@ref).

See also: [`PlainMatrix`](@ref), [`SecureMatrix`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainArray(data, context)
end

"""
    PlainArray(data::Array{<:Real}, context::SecureContext{<:OpenFHEBackend})

Constructor for data type [`PlainArray`](@ref) takes an unencrypted `data` array and a `context`
object of type `SecureContext{<:OpenFHEBackend}`. Return [`PlainArray`](@ref) with encoded but
not encrypted data. The `context` can be utilized later for encryption using [`encrypt`](@ref),
resulting in [`SecureArray`](@ref).

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`encrypt`](@ref), [`decrypt`](@ref)
[`OpenFHEBackend`](@ref)
"""
function PlainArray(data::Array{<:Real}, context::SecureContext{<:OpenFHEBackend})
    PlainArray(Vector{Float64}(vec(data)), context, size(data))
end

function PlainArray(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend}, 
                    shape)
    cc = get_crypto_context(context)
    # capacity of a single plaintext
    capacity = OpenFHE.GetBatchSize(OpenFHE.GetEncodingParams(cc))
    # split data between plaintexts, only last one can be not full
    n_plaintexts = ceil(Int, length(data)/capacity)
    plaintexts = OpenFHE.Plaintext[]
    for i in 1:n_plaintexts
        first = (i-1)*capacity + 1
        last = min(i*capacity, length(data))
        push!(plaintexts, OpenFHE.MakeCKKSPackedPlaintext(cc, data[first:last]))
    end
    plain_array = PlainArray(plaintexts, shape, capacity * n_plaintexts, context)

    plain_array
end

function Base.show(io::IO, pa::PlainArray{<:OpenFHEBackend})
    print(io, collect(pa))
end

function Base.show(io::IO, ::MIME"text/plain", pa::PlainArray{<:OpenFHEBackend})
    print(io, pa.shape, "-shaped PlainArray{OpenFHEBackend}:\n")
    Base.print_matrix(io, collect(pa))
end

"""
    collect(plain_array::PlainArray{<:OpenFHEBackend})

Decode and return the real-valued data contained in `plain_array`.

See also: [`PlainArray`](@ref), [`OpenFHEBackend`](@ref)
"""
function Base.collect(plain_array::PlainArray{<:OpenFHEBackend})
    data = Vector.(OpenFHE.GetRealPackedValue.(plain_array.data))
    plaintext_capacity = Int(capacity(plain_array) / length(plain_array.data))
    empty_places = capacity(plain_array) - length(plain_array)
    short_length = plaintext_capacity - empty_places
    keepat!(data[end], 1:short_length)
    data = reduce(vcat, data)

    Array{Float64, ndims(plain_array)}(reshape(data, plain_array.shape))
end


"""
    level(a::Union{SecureArray{<:OpenFHEBackend}, PlainArray{<:OpenFHEBackend}})

Return the number of scalings, referred to as the level, performed over `a`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`OpenFHEBackend`](@ref)
"""
function level(a::Union{SecureArray{<:OpenFHEBackend}, PlainArray{<:OpenFHEBackend}})
    maximum(Int.(OpenFHE.GetLevel.(a.data)))
end

function encrypt_impl(data::Array{<:Real}, public_key::PublicKey,
                      context::SecureContext{<:OpenFHEBackend})
    plain_array = PlainArray(data, context)
    secure_array = encrypt(plain_array, public_key)

    secure_array
end

function encrypt_impl(plain_array::PlainArray{<:OpenFHEBackend}, public_key::PublicKey)
    context = plain_array.context
    cc = get_crypto_context(context)
    ciphertexts = OpenFHE.Ciphertext[]
    for pv in plain_array.data
        push!(ciphertexts, OpenFHE.Encrypt(cc, public_key.public_key, pv))
    end
    secure_array = SecureArray(ciphertexts, size(plain_array), capacity(plain_array), context)

    secure_array
end

function decrypt_impl!(plain_array::PlainArray{<:OpenFHEBackend},
                       secure_array::SecureArray{<:OpenFHEBackend},
                       private_key::PrivateKey)
    cc = get_crypto_context(secure_array)
    for i in eachindex(secure_array.data)
        OpenFHE.Decrypt(cc, private_key.private_key, secure_array.data[i],
                        plain_array.data[i])
    end

    plain_array
end

function decrypt_impl(secure_array::SecureArray{<:OpenFHEBackend},
                      private_key::PrivateKey)
    context = secure_array.context
    plaintexts = Vector{OpenFHE.Plaintext}(undef, length(secure_array.data))
    for i in eachindex(plaintexts)
        plaintexts[i] = OpenFHE.Plaintext()
    end
    plain_array = PlainArray(plaintexts, size(secure_array), capacity(secure_array), context)

    decrypt!(plain_array, secure_array, private_key)
end

"""
    bootstrap!(secure_array::SecureArray{<:OpenFHEBackend}, num_iterations = 1,
               precision = 0)
     
Refresh a given `secure_array` to increase the multiplication depth. Supported for CKKS only.
Please refer to the OpenFHE documentation for details on the arguments `num_iterations` and
`precision`.

See also: [`SecureArray`](@ref), [`OpenFHEBackend`](@ref), [`init_bootstrapping!`](@ref)
"""
function bootstrap!(secure_array::SecureArray{<:OpenFHEBackend}, num_iterations = 1,
                    precision = 0)
    context = secure_array.context
    cc = get_crypto_context(context)
    @threaded for i in eachindex(secure_array.data)
        secure_array.data[i] = OpenFHE.EvalBootstrap(cc, secure_array.data[i],
                                                     num_iterations, precision)
    end

    secure_array
end


############################################################################################
# Arithmetic operations
############################################################################################

function add(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    @threaded for i in eachindex(sa1.data)
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), capacity(sa1), sa1.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function subtract(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    @threaded for i in eachindex(sa1.data)
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), capacity(sa1), sa1.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function subtract(pa::PlainArray{<:OpenFHEBackend}, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalSub(cc, pa.data[i], sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function subtract(scalar::Real, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalSub(cc, scalar, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function negate(sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalNegate(cc, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function multiply(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    @threaded for i in eachindex(sa1.data)
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), capacity(sa1), sa1.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    @threaded for i in eachindex(sa.data)
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), capacity(sa), sa.context)

    secure_array
end

function rotate(sa::SecureArray{<:OpenFHEBackend, 1}, shift)
    shift = shift[1]
    # crypto context
    cc = get_crypto_context(sa.context)
    # minimal required shift
    shift = shift % length(sa)
    # convert negative shift to positive one
    if shift < 0
        shift = length(sa) + shift
    end
    # only the last ciphertext can be shorter than capacity, export capacity and length
    vec_capacity = Int(capacity(sa) / length(sa.data))
    empty_places = capacity(sa) - length(sa)
    short_length = vec_capacity - empty_places
    # update required shift with respect of empty places in last ciphertext
    shift += empty_places
    # shift vector of ciphertexts, so that shift is only required in each ciphertext
    # and between direct neighbours
    shift1 = div(shift, vec_capacity)
    # for all ciphertexts before short one first rotation_index elements have to be moved from the previous ciphertext
    # operate with data stored as a vector of ciphertexts
    sv = similar(sa.data)
    sv_new = similar(sa.data)
    # rotation index for individual ciphertexts
    rotation_index = shift - vec_capacity * shift1
    
    # first shift1 ciphertexts have to be rotated by rotation_index
    for i in 1:shift1
        sv[i] = OpenFHE.EvalRotate(cc, circshift(sa.data, shift1)[i], -rotation_index)
    end
    # all other ciphertexts except last one have to be rotated by rotation_index + short_length to compensate
    # empty places in array's middle
    for i in shift1+1:length(sv)-1
        sv[i] = OpenFHE.EvalRotate(cc, circshift(sa.data, shift1)[i], -(rotation_index - empty_places))
    end
    # the last one is also shifted by rotation_index
    sv[end] = OpenFHE.EvalRotate(cc, circshift(sa.data, shift1)[end], -rotation_index)
    # mask for first rotation_index elements of each ciphertext
    mask1 = zeros(vec_capacity)
    mask1[1:rotation_index] .= 1
    # mask for remaining part of each ciphertext
    mask2 = OpenFHE.MakeCKKSPackedPlaintext(cc, 1 .- mask1)
    mask1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask1)
    @threaded for i in 1:shift1-1
        sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[i], mask1),
                                    OpenFHE.EvalMult(cc, sv[i], mask2))
    end
    # depending on how rotation_index and short_length relate, several cases are possible
    n_shift = rotation_index - empty_places
    if n_shift == 0
        # if after rotation last element of short ciphertext is already on last place, it needs only first
        # rotation_index elements from previous ciphertext
        sv_new[shift1] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                         OpenFHE.EvalMult(cc, sv[shift1], mask2))
        # due to empty place in new last ciphertext, it has to be rotated
        sv_new[end] = OpenFHE.EvalRotate(cc, sv[end], -short_length)
        # all other ciphertexts are without changes
        sv_new[shift1+1:end-1] = sv[shift1+1:end-1]
    # if last element of short ciphertext after circular shift has come back at front, it has to be moved
    # to the next ciphertext, as well as for all next ciphertexts
    elseif n_shift > 0
        # move first rotation_index elements to the short ciphertext from previous
        if shift1 > 0
            sv_new[shift1] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                             OpenFHE.EvalMult(cc, sv[shift1], mask2))
        end
        # mask for first n_shift elements 
        mask3 = zeros(vec_capacity)
        mask3[1:n_shift] .= 1
        # mask for remaining part of each ciphertext
        mask4 = OpenFHE.MakeCKKSPackedPlaintext(cc, 1 .- mask3)
        mask3 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask3)
        # move n_shift elements starting from short ciphertext upto last one
        @threaded for i in shift1+1:length(sv)-1
            sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[i], mask3),
                                        OpenFHE.EvalMult(cc, sv[i], mask4))
        end
        # last one has to be additionally rotated due to empty place
        if length(sv) > 1 || empty_places != 0
            sv_new[end] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[end], mask3),
                                          OpenFHE.EvalMult(cc, OpenFHE.EvalRotate(cc, sv[end], -short_length),
                                                           mask4))
        else
            sv_new[end] = sv[end]
        end
    # if the last element of short ciphertext didn't reach the end of ciphertext, elements
    # from next ciphertext have to be moved to the end of short ciphertext
    else
        # number of elements to shift from next ciphertext
        n_shift = -n_shift
        # mask for short_length elements after rotation_index elements
        mask3 = zeros(vec_capacity)
        mask3[1+rotation_index:short_length+rotation_index] .= 1
        mask3 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask3)
        # mask for last n_shift elements
        mask4 = zeros(vec_capacity)
        mask4[end-n_shift+1:end] .= 1
        # mask for first capacity-n_shift elements
        mask5 = OpenFHE.MakeCKKSPackedPlaintext(cc, 1 .- mask4)
        mask4 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask4)
        # short ciphertext is a combination of first rotation_index elements of previous ciphertext,
        # last n_shift elements of the next ciphertext, and itself
        sv_new[shift1] = OpenFHE.EvalAdd(cc,
                                         OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                                         OpenFHE.EvalMult(cc, sv[shift1], mask3)),
                                         OpenFHE.EvalMult(cc, circshift(sv, -1)[shift1], mask4))
        # All ciphertexts after the short one upto prelast ciphertext
        # become last n_shift elements from the next ciphertext
        @threaded for i in shift1+1:length(sv)-2
            sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv[i+1], mask4),
                                        OpenFHE.EvalMult(cc, sv[i], mask5))
        end
        # last ciphertext is rotated due to empty places
        sv_new[end] = OpenFHE.EvalRotate(cc, sv[end], -short_length)
        # prelast becomes n_shift elements from the last ciphertext
        # from positions rotation_index+1:rotation_index+n_shift
        sv_new[end-1] =  OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv_new[end], mask4), OpenFHE.EvalMult(cc, sv[end-1], mask5))
    end

    SecureArray(sv_new, size(sa), capacity(sa), sa.context)
end

function rotate(sa::SecureArray{<:OpenFHEBackend, N}, shift) where N
    # use mutable type
    shift = collect(shift)
    # minimal required shift
    shift = shift .% size(sa)
    for i in 1:N
        # convert negative shifts to positive
        if shift[i] < 0
            shift[i] = size(sa)[i] + shift[i]
        end
    end
    # length of each dimension
    lengths = ones(Int, N)
    for i in 1:N
        lengths[i] = prod(size(sa)[1:i-1])
    end
    # combination of all shifts (in each dimension) in 1D shift
    main_1d_shift = sum(shift .* lengths)
    # compute all combinations of dimensions (except last one and with non-zero shift)
    # to retrieve cyclicity
    combinations = Vector{Int}[]
    for i in 1:N-1
        if shift[i] != 0
            append!(combinations, push!.(copy.(combinations), i))
            push!(combinations, [i])
        end
    end
    # mask for main part shifted by `main_1d_shift`
    main_mask = ones(Int, size(sa))
    # masks to retrieve cyclicity, for each of `combinations`
    masks = []
    # indices for array iteration
    indices = Vector(undef, N)
    # additional 1D shifts for masked dimension combinations
    masked_1d_shift = []
    for i in combinations
        push!(masked_1d_shift, main_1d_shift)
        # correctly rotated elements 
        indices[:] .= range.(1, size(sa) .- shift)
        indices[end] = range(1, size(sa)[end])
        # correct indices to include only elements that are
        # shifted in the given combination i
        for j in i
            indices[j] = (size(sa)[j] - shift[j] + 1):size(sa)[j]
            masked_1d_shift[end] -= lengths[j+1]
        end
        push!(masks, zeros(Int, size(sa)))
        masks[end][indices...] .= 1
        main_mask[indices...] .= 0
    end
    # convert masks to PlainArray's
    main_mask = PlainArray(vec(main_mask), sa.context)
    for i in eachindex(masks)
        masks[i] = PlainArray(vec(masks[i]), sa.context)
    end
    # operate with N-dimensional array in form of 1D
    sv = SecureArray(sa.data, (length(sa),), capacity(sa), sa.context)
    # apply main shift
    sv_new = circshift(sv * main_mask, main_1d_shift)
    # correct positions of elements in each dimension combination
    for i in eachindex(masks)
        sv_new += circshift(sv * masks[i], masked_1d_shift[i])
    end

    SecureArray(sv_new.data, size(sa), capacity(sa), sa.context)
end
