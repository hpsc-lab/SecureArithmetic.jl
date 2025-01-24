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

Note: To ensure that all shifts for intrinsic operations are precomputed, use
`init_array_rotation!`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref),
[`init_array_rotation!`](@ref)
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

############################################################################################
# Array
############################################################################################
"""
    init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                         shift::Union{Integer, NTuple{N, Integer}}, shape::NTuple{N, Integer})

Generate all required rotation keys for use with `circshift` for the
rotation index in `shift` using the `private_key`. The keys are stored in the given `context`.

Note: To precompute rotation keys for an exactly specified rotation index, use `init_rotation!`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref),
[`init_rotation!`](@ref)
"""
function init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                              shift::Union{Integer, NTuple{N, Integer}}, shape::NTuple{N, Integer}) where N
    init_array_rotation!(context, private_key, [shift], shape)
end

"""
    init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                         shifts::Vector{<:Union{<:Integer, <:NTuple{N, <:Integer}}},
                         shape::NTuple{N, Integer})

Generate all required rotation keys for use with `circshift` for the
rotation indexes in `shifts` using the `private_key`. The keys are stored in the given `context`.

Note: To precompute rotation keys for exactly specified rotation indexes, use `init_rotation!`.

See also: [`SecureContext`](@ref), [`OpenFHEBackend`](@ref), [`PrivateKey`](@ref),
[`init_rotation!`](@ref)
"""
function init_array_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,
                              shifts::Vector{<:Union{<:Integer, <:NTuple{N, <:Integer}}},
                              shape::NTuple{N, Integer}) where N
    cc = get_crypto_context(context)
    # Get shifts for precompilation
    shifts_ = get_shifts_array(context, shifts, shape)
    # All shifts stored in shifts_ correspond to Base.circshift, but to use with OpenFHE, all shifts
    # have to be negated.
    OpenFHE.EvalRotateKeyGen(cc, private_key.private_key, -unique(shifts_))

    nothing
end

function get_shifts_array(context::SecureContext{<:OpenFHEBackend}, shifts::Vector{<:Tuple{<:Integer}},
                          shape::Tuple{Integer})
    get_shifts_array(context, getproperty.(shifts,1), shape)
end

function get_shifts_array(context::SecureContext{<:OpenFHEBackend}, shifts::Vector{<:Integer},
                          shape::Tuple{Integer})
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
        # convert negative shift to positive one
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

#=function get_shifts_array(context::SecureContext{<:OpenFHEBackend}, shifts::Vector{<:NTuple{N, <:Integer}},
                          shape::NTuple{N, Integer}) where N
    
    # calculate length of each dimension
    lengths = ones(Int, N)
    for i in range(2, N)
        lengths[i] = prod(shape[1:i-1])
    end
    # assemble 1d shifts
    shifts_1d = Int[]
    for shift in shifts
        # use mutable type
        shift = collect(shift)
        # minimal required shift
        shift = shift .% shape
        # convert negative shift to positive
        for i in range(1, N)
            if shift[i] < 0
                shift[i] = shape[i] + shift[i]
            end
        end
        # shift for each dimension
        shift1 = zeros(Int, N)
        for i in range(1, N-1)
            shift1[i] = shift[i] * lengths[i]
            push!(shifts_1d, shift1[i] - lengths[i+1])
        end
        push!(shifts_1d, shift[end] * lengths[end])
    end

    get_shifts_array(context, shifts_1d, (prod(shape),))
end=#

function get_shifts_array(context::SecureContext{<:OpenFHEBackend}, shifts::Vector{<:NTuple{N, <:Integer}},
    shape::NTuple{N, Integer}) where N

    # calculate length of each dimension
    lengths = ones(Int, N)
    for i in range(2, N)
        lengths[i] = prod(shape[1:i-1])
    end
    # assemble 1d shifts
    shifts_1d = Int[]
    for shift in shifts
        # use mutable type
        shift = collect(shift)
        # minimal required shift
        shift = shift .% shape
        # convert negative shift to positive
        for i in range(1, N)
            if shift[i] < 0
                shift[i] = shape[i] + shift[i]
            end
        end
        # shift for each dimension
        shift1 = zeros(Int, N)
        for i in range(1, N)
            shift1[i] = shift[i] * lengths[i]
        end
        # shift for main part of array
        main_shift = sum(shift1)
        push!(shifts_1d, sum(shift1))
        # all possible combinations of dimensions
        combinations = compute_dimension_combinations(N-1, shift[1:N-1])
        # shifts to retrieve cyclicity
        for i in combinations
            push!(shifts_1d, main_shift)
            for j in i
                shifts_1d[end] -= lengths[j+1]
            end
        end
    end

    get_shifts_array(context, shifts_1d, (prod(shape),))
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
    keepat!.(data, range.(1, plain_array.lengths))
    data = reduce(vcat, data)

    Array{Float64, length(plain_array.shape)}(reshape(data, plain_array.shape))
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
    Threads.@threads for i in range(1, length(secure_array.data))
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
    Threads.@threads for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function add(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalAdd(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    Threads.@threads for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(pa::PlainArray{<:OpenFHEBackend}, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, pa.data[i], sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function subtract(scalar::Real, sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalSub(cc, scalar, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function negate(sa::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalNegate(cc, sa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function multiply(sa1::SecureArray{<:OpenFHEBackend}, sa2::SecureArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa1)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa1.data))
    Threads.@threads for i in range(1, length(sa1.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa1.data[i], sa2.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa1), sa1.lengths, sa1.capacities, sa1.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, pa::PlainArray{<:OpenFHEBackend})
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], pa.data[i])
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function multiply(sa::SecureArray{<:OpenFHEBackend}, scalar::Real)
    cc = get_crypto_context(sa)
    ciphertexts = Vector{OpenFHE.Ciphertext}(undef, length(sa.data))
    Threads.@threads for i in range(1, length(sa.data))
        ciphertexts[i] = OpenFHE.EvalMult(cc, sa.data[i], scalar)
    end
    secure_array = SecureArray(ciphertexts, size(sa), sa.lengths, sa.capacities, sa.context)

    secure_array
end

function rotate(sa::SecureArray{<:OpenFHEBackend, 1}, shift::Union{Integer, Tuple{Integer}}; wrap_by)
    # wrap by capacity makes sense only for single ciphertext
    if wrap_by == :capacity && length(sa.data) == 1
        cc = get_crypto_context(sa)
        # We use `-shift` to match Julia's usual `circshift` direction
        ciphertext_rotated = OpenFHE.EvalRotate(cc, sa.data[1], -shift[1])
        return SecureArray([ciphertext_rotated], size(sa), sa.lengths, sa.capacities, sa.context)
    else
        return rotate(sa, shift[1])
    end
end

function rotate(sa::SecureArray{<:OpenFHEBackend, 1}, shift::Tuple{Integer})
    rotate(sa, shift[1])
end

function rotate(sa::SecureArray{<:OpenFHEBackend, 1}, shift::Integer)
    # crypto context
    cc = get_crypto_context(sa.context)
    # minimal required shift
    shift = shift % length(sa)
    # convert negative shift to positive one
    if shift < 0
        shift = length(sa) + shift
    end
    # operate with data stored as a vector of ciphertexts
    sv = sa.data
    # only the last vector can be smaller than capacity, export capacity and length
    vec_capacity = sa.capacities[end]
    short_length = sa.lengths[end]
    empty_places = vec_capacity - short_length
    # update required shift with respect of empty places in last vector
    shift += empty_places
    # shift secure vectors, so that shift is only required in each secure vector
    # and between direct neighbours
    shift1 = div(shift, vec_capacity)
    sv = circshift(sv, shift1)
    # shift for individual vectors
    shift2 = shift - vec_capacity * shift1
    # if the last vector is also full, rotation is simpler
    if empty_places == 0
        # shift each vector
        Threads.@threads for i in range(1, length(sv))
            sv[i] = OpenFHE.EvalRotate(cc, sv[i], -shift2)
        end
        # first shift2 elements of each vector have to be moved 
        # to the first shift2 elements of next vector if there are more than one ciphertexts 
        if length(sv) > 1
            sv_new = similar(sv)
            # mask for fist shift2 elements of each vector
            mask1 = zeros(vec_capacity)
            mask1[1:shift2] .= 1
            mask1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask1)
            # mask for remaining part of each vector
            mask2 = zeros(vec_capacity)
            mask2[shift2+1:end] .= 1
            mask2 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask2)
            Threads.@threads for i in range(1, length(sv))
                sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[i], mask1),
                                            OpenFHE.EvalMult(cc, sv[i], mask2))
            end
            sv = sv_new
        end
    # next case when after rotating a whole array (not individual ciphertexts) 
    # short vector is already the last one 
    elseif shift1 % length(sv) == 0
        # if short vector is at the end, shift does not need to be corrected due to its empty places 
        # (except for the short vector), change the shift back
        shift2 -= empty_places
        # rotate all vectors except the last one
        Threads.@threads for i in range(1, length(sv)-1)
            sv[i] = OpenFHE.EvalRotate(cc, sv[i], -shift2)
        end
        # rotate the last considering empty places
        sv[end] = OpenFHE.EvalRotate(cc, sv[end], -(shift2 + empty_places))
        # first shift2 elements of each vector have to be moved to the next one and rotate the last
        # vector additionally
        sv_new = similar(sv)
        # mask for fist shift2 elements of each vector
        mask1 = zeros(vec_capacity)
        mask1[1:shift2] .= 1
        mask1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask1)
        # mask for remaining part of each vector
        mask2 = zeros(vec_capacity)
        mask2[shift2+1:end] .= 1
        mask2 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask2)
        Threads.@threads for i in range(1, length(sv)-1)
            sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[i], mask1),
                                        OpenFHE.EvalMult(cc, sv[i], mask2))
        end
        # The last vector have to be also additionally rotated by its length, so that elements stay
        # at correct position
        sv_new[end] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[end], mask1),
                                      OpenFHE.EvalMult(cc, OpenFHE.EvalRotate(cc, sv[end], -short_length), mask2))
        sv = sv_new
    # The last case when short vector is not the last one and its empty places have to be filled,
    # so that the last vector still the only short one
    else
        # first shift1 vectors have to be rotated by shift2
        Threads.@threads for i in range(1, shift1)
            sv[i] = OpenFHE.EvalRotate(cc, sv[i], -shift2)
        end
        # all other vectors except last one have to be rotated by shift2 + short_length to compensate
        # empty places in array's middle
        Threads.@threads for i in range(shift1+1, length(sv)-1)
            sv[i] = OpenFHE.EvalRotate(cc, sv[i], -(shift2 + short_length))
        end
        # the last one is also shifted by shift2
        sv[end] = OpenFHE.EvalRotate(cc, sv[end], -shift2)
        # for all vectors before short first shift2 elements have to be moved from the previous vector
        sv_new = similar(sv)
        # mask for fist shift2 elements of each vector
        mask1 = zeros(vec_capacity)
        mask1[1:shift2] .= 1
        mask1 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask1)
        # mask for remaining part of each vector
        mask2 = zeros(vec_capacity)
        mask2[shift2+1:end] .= 1
        mask2 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask2)
        Threads.@threads for i in range(1, shift1-1)
            sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[i], mask1),
                                        OpenFHE.EvalMult(cc, sv[i], mask2))
        end
        # depending on how shift2 and short_length relate, several cases are possible
        if shift2 == empty_places
            # if after rotation last element of short vector is already on last place, it needs only first
            # shift2 elements from previous vector
            sv_new[shift1] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                             OpenFHE.EvalMult(cc, sv[shift1], mask2))
            # due to empty place in new last vector, it has to be rotated
            sv_new[end] = OpenFHE.EvalRotate(cc, sv[end], -short_length)
            # all other vectors are without changes
            sv_new[shift1+1:end-1] = sv[shift1+1:end-1]
        # if last element of short vector after circular shift has come back at front, it has to be moved
        # to the next vector, as well as for all next vectors
        elseif shift2 > empty_places
            # move first shift2 elements to the short vector from previous
            sv_new[shift1] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                             OpenFHE.EvalMult(cc, sv[shift1], mask2))
            # number of elements to shift from short vector to the next one
            n_shift = shift2 - empty_places
            # mask for first n_shift elements 
            mask3 = zeros(vec_capacity)
            mask3[1:n_shift] .= 1
            mask3 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask3)
            # mask for remaining part of each vector
            mask4 = zeros(vec_capacity)
            mask4[n_shift+1:end] .= 1
            mask4 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask4)
            # move n_shift elements starting from short vector upto last one
            Threads.@threads for i in range(shift1+1, length(sv)-1)
                sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv[i-1], mask3),
                                            OpenFHE.EvalMult(cc, sv[i], mask4))
            end
            # last one has to be additionally rotated due to empty place
            sv_new[end] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv[end-1], mask3),
                                          OpenFHE.EvalMult(cc, OpenFHE.EvalRotate(cc, sv[end], -short_length),
                                                           mask4))
        # if the last element of short vector didn't reach the end of vector, elements
        # from previous vector have to be moved to the end of short vector
        else
            # number of elements to shift from next vector
            n_shift = empty_places - shift2
            # mask for short_length elements after shift2 elements
            mask3 = zeros(vec_capacity)
            mask3[1+shift2:short_length+shift2] .= 1
            mask3 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask3)
            # mask for last n_shift elements
            mask4 = zeros(vec_capacity)
            mask4[end-n_shift+1:end] .= 1
            mask4 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask4)
            # mask for first capacity-n_shift elements
            mask5 = zeros(vec_capacity)
            mask5[1:end-n_shift] .= 1
            mask5 = OpenFHE.MakeCKKSPackedPlaintext(cc, mask5)
            # short vector is a combination first shift2 elements of previous vector,
            # last n_shift elements of the next vector, and itself
            sv_new[shift1] = OpenFHE.EvalAdd(cc,
                                             OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, circshift(sv, 1)[shift1], mask1),
                                                             OpenFHE.EvalMult(cc, sv[shift1], mask3)),
                                             OpenFHE.EvalMult(cc, circshift(sv, -1)[shift1], mask4))
            # All vectors after the short one upto prelast vector
            # become last n_shift elements from the next vector
            Threads.@threads for i in range(shift1+1, length(sv)-2)
                sv_new[i] = OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv[i+1], mask4),
                                            OpenFHE.EvalMult(cc, sv[i], mask5))
            end
            # last vector is rotated due to empty places
            sv_new[end] = OpenFHE.EvalRotate(cc, sv[end], -short_length)
            # prelast becomes n_shift elements from the last vector
            # from positions shift2+1:shift2+n_shift
            sv_new[end-1] =  OpenFHE.EvalAdd(cc, OpenFHE.EvalMult(cc, sv_new[end], mask4), OpenFHE.EvalMult(cc, sv[end-1], mask5))
        end
        # update vector
        sv = sv_new
    end

    SecureArray(sv, size(sa), sa.lengths, sa.capacities, sa.context)
end

#=function rotate(sa::SecureArray{<:OpenFHEBackend, N}, shift::NTuple{N, Integer}) where N
    # use mutable type
    shift = collect(shift)
    # minimal required shift
    shift = shift .% size(sa)
    for i in range(1, N)
        # convert negative shifts to positive
        if shift[i] < 0
            shift[i] = size(sa)[i] + shift[i]
        end
    end
    shift1 = zeros(Int, N)
    lengths = ones(Int, N)
    for i in range(1, N)
        # calculate length of each dimension
        lengths[i] = prod(size(sa)[1:i-1])
        # Shift for each dimension
        shift1[i] = shift[i] * lengths[i]
    end
    # masks for incorrectly placed elements in each dimension
    masks = []
    anti_masks = []
    # indices for array iteration
    indices = Vector{Any}(undef, N)
    for i in range(1, N-1)
        push!(masks, zeros(size(sa)))
        push!(anti_masks, zeros(size(sa)))
        indices[:] .= range.(1, size(sa))
        indices[i] = (size(sa)[i] - shift[i] + 1):size(sa)[i]
        masks[i][indices...] .= 1.0
        anti_masks[i] = 1 .- masks[i]
    end
    # convert masks to PlainArray's
    for i in range(1, N-1)
        masks[i] = PlainArray(vec(masks[i]), sa.context)
        anti_masks[i] = PlainArray(vec(anti_masks[i]), sa.context)
    end
    # operate with N-dimensional array in form of 1D
    sv = SecureArray(sa.data, (length(sa),), sa.lengths, sa.capacities, sa.context)
    # correct positions of elements in each dimension
    for i in range(1, N-1)
        if shift[i] != 0
            sv = rotate(sv*anti_masks[i], shift1[i]) + rotate(sv * masks[i], shift1[i] - lengths[i+1])
        end
    end
    sv = rotate(sv, shift1[end])

    SecureArray(sv.data, size(sa), sa.lengths, sa.capacities, sa.context)
end=#

function compute_dimension_combinations(N::Integer, shift::Vector{<:Integer})
    if N == 1
        if shift[1] != 0
            return [[1]]
        else
            return []
        end
    end
    combinations = compute_dimension_combinations(N-1, shift[1:N-1])
    if shift[N] != 0
        n = length(combinations)
        append!(combinations, push!.(copy.(combinations), N))
        push!(combinations, [N])
    end
    return combinations
end

function rotate(sa::SecureArray{<:OpenFHEBackend, N}, shift::NTuple{N, Integer}) where N
    # use mutable type
    shift = collect(shift)
    # minimal required shift
    shift = shift .% size(sa)
    for i in range(1, N)
        # convert negative shifts to positive
        if shift[i] < 0
            shift[i] = size(sa)[i] + shift[i]
        end
    end
    shift1 = zeros(Int, N)
    lengths = ones(Int, N)
    for i in range(1, N)
        # calculate length of each dimension
        lengths[i] = prod(size(sa)[1:i-1])
        # Shift for each dimension
        shift1[i] = shift[i] * lengths[i]
    end
    # shift for main part
    main_shift = sum(shift1)
    # masks
    masks = []
    main_mask = ones(Int, size(sa))
    # indices for array iteration
    indices = Vector(undef, N)
    # shifts to retrieve cyclicity
    shift_masked = []
    # compute all combinations of dimensions (except last one)
    combinations = compute_dimension_combinations(N-1, shift[1:N-1])
    # mask for main part
    for i in range(1, N-1)
        indices[:] .= range.(1, size(sa))
        indices[i] = (size(sa)[i] - shift[i] + 1):size(sa)[i]
        main_mask[indices...] .= 0
    end
    # masks to retrieve cyclicity
    for i in combinations
        push!(shift_masked, main_shift)
        indices[:] .= range.(1, size(sa) .- shift)
        indices[end] = range.(1, size(sa)[end])
        for j in i
            indices[j] = (size(sa)[j] - shift[j] + 1):size(sa)[j]
            shift_masked[end] -= lengths[j+1]
        end
        push!(masks, zeros(Int, size(sa)))
        masks[end][indices...] .= 1
    end
    # convert masks to PlainArray's
    main_mask = PlainArray(vec(main_mask), sa.context)
    for i in range(1, length(masks))
        masks[i] = PlainArray(vec(masks[i]), sa.context)
    end
    # operate with N-dimensional array in form of 1D
    sv = SecureArray(sa.data, (length(sa),), sa.lengths, sa.capacities, sa.context)
    # apply main shift
    sv_new = circshift(sv * main_mask, main_shift)
    # correct positions of elements in each dimension combination
    for i in range(1, length(masks))
        sv_new += circshift(sv * masks[i], shift_masked[i])
    end

    SecureArray(sv_new.data, size(sa), sa.lengths, sa.capacities, sa.context)
end
