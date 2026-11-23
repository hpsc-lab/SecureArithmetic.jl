abstract type AbstractCryptoBackend end

"""
    SecureContext

A structure used to generalize `CryptoContext` defined in OpenFHE.jl for unencrypted data, to
maximize utilization of the same code for both plaintext and ciphertext.

See also: [`OpenFHEBackend`](@ref), [`Unencrypted`](@ref)
"""
struct SecureContext{CryptoBackendT <: AbstractCryptoBackend}
    backend::CryptoBackendT
end

function Base.show(io::IO, v::SecureContext)
    print("SecureContext{", backend_name(v), "}()")
end

"""
    PrivateKey

Holds a private key that is used for decryption in [`decrypt`](@ref).

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`decrypt`](@ref)
"""
struct PrivateKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    private_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PrivateKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end

function Base.show(io::IO, key::PrivateKey)
    print("PrivateKey{", backend_name(key), "}()")
end

"""
    PublicKey

Holds a public key that is used for encryption in [`encrypt`](@ref).

See also: [`PlainVector`](@ref), [`SecureVector`](@ref), [`encrypt`](@ref)
"""
struct PublicKey{CryptoBackendT <: AbstractCryptoBackend, KeyT}
    public_key::KeyT
    context::SecureContext{CryptoBackendT}

    function PublicKey(context::SecureContext{CryptoBackendT}, key) where CryptoBackendT
        new{CryptoBackendT, typeof(key)}(key, context)
    end
end

function Base.show(io::IO, key::PublicKey)
    print("PublicKey{", backend_name(key), "}()")
end

"""
    SecureArray{Backend, N, DataT}

Holds an encrypted `N`-dimensional array for arithmetic operations.
Can be converted to a `PlainArray` using [`decrypt`](@ref).

See also: [`PlainArray`](@ref), [`decrypt`](@ref)
"""
struct SecureArray{CryptoBackendT <: AbstractCryptoBackend, N, DataT}
    data::DataT
    shape::NTuple{N, Int}
    capacity::Int
    context::SecureContext{CryptoBackendT}

    function SecureArray(data, shape, capacity,
                         context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, length(shape), typeof(data)}(data, shape, capacity, context)
    end
end

"""
    SecureVector{Backend, DataT}

Alias for SecureArray{Backend, 1, DataT}. Holds encrypted vector data for arithmetic operations.
Can be converted to a `PlainVector` using [`decrypt`](@ref).

See also: [`PlainVector`](@ref), [`SecureArray`](@ref), [`decrypt`](@ref)
"""
const SecureVector{Backend, DataT} = SecureArray{Backend, 1, DataT}

"""
    SecureMatrix{Backend, DataT}

Alias for SecureArray{Backend, 2, DataT}. Holds encrypted matrix data for arithmetic operations.
Can be converted to a `PlainMatrix` using [`decrypt`](@ref).

See also: [`PlainMatrix`](@ref), [`SecureArray`](@ref), [`decrypt`](@ref)
"""
const SecureMatrix{Backend, DataT} = SecureArray{Backend, 2, DataT}

"""
    PlainArray{Backend, N, DataT}

Holds an encoded - but not encrypted - `N`-dimensional array
for arithmetic operations. Can be converted to a `SecureArray` using [`encrypt`](@ref).

See also: [`SecureArray`](@ref), [`encrypt`](@ref)
"""
struct PlainArray{CryptoBackendT <: AbstractCryptoBackend, N, DataT}
    data::DataT
    shape::NTuple{N, Int}
    capacity::Int
    context::SecureContext{CryptoBackendT}

    function PlainArray(data, shape, capacity,
                        context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, length(shape), typeof(data)}(data, shape, capacity, context)
    end
end

"""
    PlainVector{Backend, DataT}

Alias for PlainArray{Backend, 1, DataT}. Holds encoded - but not encrypted - vector data for
arithmetic operations. Can be converted to a `SecureVector` using [`encrypt`](@ref).

See also: [`SecureVector`](@ref), [`PlainArray`](@ref), [`encrypt`](@ref)
"""
const PlainVector{Backend, DataT} = PlainArray{Backend, 1, DataT}

"""
    PlainMatrix{Backend, DataT}

Alias for PlainArray{Backend, 2, DataT}. Holds encoded - but not encrypted - matrix data for
arithmetic operations. Can be converted to a `SecureMatrix` using [`encrypt`](@ref).

See also: [`SecureMatrix`](@ref), [`PlainArray`](@ref), [`encrypt`](@ref)
"""
const PlainMatrix{Backend, DataT} = PlainArray{Backend, 2, DataT}

"""
    size(a::Union{PlainArray, SecureArray})

Return the current shape of `a`.

See also: [`SecureArray`](@ref), [`PlainArray`](@ref)
"""
Base.size(a::Union{PlainArray, SecureArray}) = a.shape

"""
    size(a::Union{PlainArray, SecureArray}, d::Int)

Return the current length of `d`th dimension of `a`.

See also: [`SecureArray`](@ref), [`PlainArray`](@ref)
"""
Base.size(a::Union{PlainArray, SecureArray}, d::Int) = a.shape[d]

"""
    length(a::Union{PlainArray, SecureArray})

Return the current length of `a`, i.e., the number of container elements in use.
Note that this might be less than its maximum [`capacity`](@ref).

See also: [`capacity`](@ref), [`SecureArray`](@ref), [`PlainArray`](@ref)
"""
Base.length(a::Union{PlainArray, SecureArray}) = prod(a.shape)

"""
    ndims(a::Union{PlainArray, SecureArray})

Return the number of dimensions of `a`.

See also: [`SecureArray`](@ref), [`PlainArray`](@ref)
"""
Base.ndims(a::Union{PlainArray, SecureArray}) = length(a.shape)

"""
    capacity(a::Union{PlainArray, SecureArray})

Return the current capacity of `a`, i.e., the maximum number of elements the container may
hold. Note that this might be more than its current [`length`](@ref).

See also: [`length`](@ref), [`SecureArray`](@ref), [`PlainArray`](@ref)
"""
capacity(a::Union{PlainArray, SecureArray}) = a.capacity

"""
    reshape(a::SecureArray, shape)

Return a `SecureArray` with the same data but a different shape.
The new shape must have the same total number of elements as the original.

See also: [`SecureArray`](@ref)
"""
function Base.reshape(a::SecureArray, shape::NTuple{M, Int}) where M
    if prod(shape) != length(a)
        throw(DimensionMismatch("new shape $(shape) is incompatible with array of length $(length(a))"))
    end
    SecureArray(a.data, shape, a.capacity, a.context)
end

Base.reshape(a::SecureArray, dims::Int...) = reshape(a, dims)

"""
    reshape(a::PlainArray, shape)

Return a `PlainArray` with the same data but a different shape.
The new shape must have the same total number of elements as the original.

See also: [`PlainArray`](@ref)
"""
function Base.reshape(a::PlainArray, shape::NTuple{M, Int}) where M
    if prod(shape) != length(a)
        throw(DimensionMismatch("new shape $(shape) is incompatible with array of length $(length(a))"))
    end
    PlainArray(a.data, shape, a.capacity, a.context)
end

Base.reshape(a::PlainArray, dims::Int...) = reshape(a, dims)

############################################################################################
# Packed arrays
############################################################################################

# Smallest power of two that is `>= n`, with `next_power_of_two(0) == 1`.
next_power_of_two(n::Integer) = nextpow(2, max(n, 1))

"""
    PlainArrayPacked{Backend, N, ArrayT}

Holds an encoded - but not encrypted - `N`-dimensional array in *packed* layout, which is the
layout every matrix multiplication runs on. Can be converted to a [`SecureArrayPacked`](@ref)
using [`encrypt`](@ref).

Packing does two things to the data:

1. every dimension is zero-padded to the next power of two, and
2. the resulting block is *tiled*, i.e. repeated, so that it fills the underlying storage
   completely (`length == capacity`).

A dimension longer than `max_block_size` is cut into blocks of that size instead, each of
which is padded and tiled as above and fills one ciphertext of its own. `padded_shape` is then
the padded shape of one block, and the blocks are stored one after another, in column-major
order of the block grid.

Together they make a rotation of the packed array a plain, level-free rotation of the
underlying ciphertext: the block length divides the slot count exactly, so the wrap-around of
a block-cyclic shift is supplied by the neighbouring tile. An unpacked [`PlainArray`](@ref)
whose length is below its capacity has to synthesize that wrap-around with masks instead,
which costs a multiplicative level per rotation.

The user-visible shape is the unpadded `shape`; [`collect`](@ref) and [`decrypt`](@ref) crop
back to it.

See also: [`SecureArrayPacked`](@ref), [`PlainArray`](@ref), [`encrypt`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
struct PlainArrayPacked{CryptoBackendT <: AbstractCryptoBackend, N, ArrayT}
    array::ArrayT
    shape::NTuple{N, Int}
    padded_shape::NTuple{N, Int}

    function PlainArrayPacked(array::PlainArray{CryptoBackendT, 1}, shape::NTuple{N, Int},
                              padded_shape::NTuple{N, Int}) where {CryptoBackendT, N}
        new{CryptoBackendT, N, typeof(array)}(array, shape, padded_shape)
    end
end

"""
    SecureArrayPacked{Backend, N, ArrayT}

Holds an encrypted `N`-dimensional array in *packed* layout. Can be converted to a
[`PlainArrayPacked`](@ref) using [`decrypt`](@ref). See [`PlainArrayPacked`](@ref) for what
packing means and why it matters.

See also: [`PlainArrayPacked`](@ref), [`SecureArray`](@ref), [`decrypt`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
struct SecureArrayPacked{CryptoBackendT <: AbstractCryptoBackend, N, ArrayT}
    array::ArrayT
    shape::NTuple{N, Int}
    padded_shape::NTuple{N, Int}

    function SecureArrayPacked(array::SecureArray{CryptoBackendT, 1}, shape::NTuple{N, Int},
                               padded_shape::NTuple{N, Int}) where {CryptoBackendT, N}
        new{CryptoBackendT, N, typeof(array)}(array, shape, padded_shape)
    end
end

"""
    PlainMatrixPacked{Backend, ArrayT}

Alias for `PlainArrayPacked{Backend, 2, ArrayT}`.

See also: [`PlainArrayPacked`](@ref)
"""
const PlainMatrixPacked{Backend, ArrayT} = PlainArrayPacked{Backend, 2, ArrayT}

"""
    PlainVectorPacked{Backend, ArrayT}

Alias for `PlainArrayPacked{Backend, 1, ArrayT}`.

See also: [`PlainArrayPacked`](@ref)
"""
const PlainVectorPacked{Backend, ArrayT} = PlainArrayPacked{Backend, 1, ArrayT}

"""
    SecureMatrixPacked{Backend, ArrayT}

Alias for `SecureArrayPacked{Backend, 2, ArrayT}`.

See also: [`SecureArrayPacked`](@ref)
"""
const SecureMatrixPacked{Backend, ArrayT} = SecureArrayPacked{Backend, 2, ArrayT}

"""
    SecureVectorPacked{Backend, ArrayT}

Alias for `SecureArrayPacked{Backend, 1, ArrayT}`.

See also: [`SecureArrayPacked`](@ref)
"""
const SecureVectorPacked{Backend, ArrayT} = SecureArrayPacked{Backend, 1, ArrayT}

# Anything in packed layout, encrypted or not. Spelled out as an alias because it carries the
# backend and the dimension through the element-wise operators in `arithmetic.jl`.
const AnyArrayPacked{Backend, N} = Union{PlainArrayPacked{Backend, N},
                                         SecureArrayPacked{Backend, N}}

# Anything in *flat* layout, encrypted or not, i.e. the ordinary unpadded and untiled storage of
# a `PlainArray`/`SecureArray`. Spelled out as an alias for the same reason as `AnyArrayPacked`,
# and named after the layout rather than after being the usual one.
const AnyArrayFlat{Backend, N} = Union{PlainArray{Backend, N}, SecureArray{Backend, N}}

# The operand pairs a matrix product accepts. Both operands have to be in the same layout: the
# kernel runs on the packed layout, so a pair of flat operands is packed on the way in and
# unpacked again on the way out, see `as_packed` and `as_unpacked`.
const AnyFlatMatrix{Backend} = AnyArrayFlat{Backend, 2}
const AnyFlatVector{Backend} = AnyArrayFlat{Backend, 1}
const AnyPackedMatrix{Backend} = AnyArrayPacked{Backend, 2}
const AnyPackedVector{Backend} = AnyArrayPacked{Backend, 1}

# Wrap the result of an operation on the inner array back up, picking the constructor that
# matches whether it is encrypted or not.
pack_result(a::PlainArray, shape, padded_shape) = PlainArrayPacked(a, shape, padded_shape)
pack_result(a::SecureArray, shape, padded_shape) = SecureArrayPacked(a, shape, padded_shape)

"""
    size(a::Union{PlainArrayPacked, SecureArrayPacked})

Return the unpadded shape of `a`, i.e. the shape of the data it was created from.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref)
"""
Base.size(a::Union{PlainArrayPacked, SecureArrayPacked}) = a.shape

# The remaining shape accessors mirror the unpacked ones, on the unpadded shape
Base.size(a::Union{PlainArrayPacked, SecureArrayPacked}, d::Int) = a.shape[d]
Base.length(a::Union{PlainArrayPacked, SecureArrayPacked}) = prod(a.shape)
Base.ndims(a::Union{PlainArrayPacked, SecureArrayPacked}) = length(a.shape)

"""
    capacity(a::Union{PlainArrayPacked, SecureArrayPacked})

Return the number of slots the packed storage of `a` occupies. Packing fills its storage
completely, so this is also the length of the underlying array.

See also: [`length`](@ref), [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref)
"""
capacity(a::Union{PlainArrayPacked, SecureArrayPacked}) = capacity(a.array)

# Length of one padded block, i.e. the period of the tiling.
block_length(a::Union{PlainArrayPacked, SecureArrayPacked}) = prod(a.padded_shape)

# Number of blocks per dimension
block_grid(shape, padded_shape) = cld.(shape, padded_shape)
block_grid(a::Union{PlainArrayPacked, SecureArrayPacked}) = block_grid(a.shape, a.padded_shape)
# Total number of blocks
n_blocks(a::Union{PlainArrayPacked, SecureArrayPacked}) = prod(block_grid(a))

# Length of the storage of one block, which holds its tiles.
block_storage(a::Union{PlainArrayPacked, SecureArrayPacked}) = capacity(a) ÷ n_blocks(a)

# Number of times the padded block is repeated in the storage of each block.
n_tiles(a::Union{PlainArrayPacked, SecureArrayPacked}) = block_storage(a) ÷ block_length(a)

# `shape` with trailing dimensions of length one appended or dropped to make it
# `M`-dimensional.
pad_shape(shape::NTuple{N, Int}, M::Integer) where N = ntuple(i -> i <= N ? shape[i] : 1, M)

"""
    reshape(a::Union{PlainArrayPacked, SecureArrayPacked}, shape)

Return a packed array with the same data but a different shape. Only shapes that append or
drop trailing dimensions of length one are allowed, since any other reshape would have to
re-pad the data. In particular, a packed vector can be viewed as a packed `d×1` matrix.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref)
"""
function Base.reshape(a::Union{PlainArrayPacked, SecureArrayPacked},
                      shape::NTuple{M, Int}) where M
    if prod(shape) != length(a) || shape != pad_shape(size(a), M)
        throw(DimensionMismatch("new shape $(shape) is incompatible with packed array of " *
                                "shape $(size(a))"))
    end
    # Only the metadata changes: appending or dropping trailing dimensions of length one
    # leaves both the block length and the column-major data layout untouched
    pack_result(a.array, shape, pad_shape(a.padded_shape, M))
end

Base.reshape(a::Union{PlainArrayPacked, SecureArrayPacked}, dims::Int...) = reshape(a, dims)

"""
    collect(a::PlainArrayPacked)

Decode and return the real-valued data contained in `a`, cropped back to its unpadded shape.

The padded block is laid out in Julia's column-major order, so the unpadded data is *not* a
prefix of the flattened storage: it is the top-left sub-block of the padded block.

See also: [`PlainArrayPacked`](@ref)
"""
function Base.collect(a::PlainArrayPacked)
    flat = vec(collect(a.array))
    if n_blocks(a) > 1
        # Every block is the top-left sub-block of its padded block, at the start of its storage
        grid = block_grid(a)
        full = zeros(Float64, grid .* a.padded_shape)
        for (b, g) in enumerate(CartesianIndices(grid))
            first = (b - 1) * block_storage(a)
            block = Base.reshape(view(flat, first+1:first+block_length(a)), a.padded_shape)
            full[map((i, p) -> (i-1)*p+1:i*p, Tuple(g), a.padded_shape)...] = block
        end
        return full[map(Base.OneTo, a.shape)...]
    end
    padded = Base.reshape(view(flat, 1:block_length(a)), a.padded_shape)
    Array{Float64, ndims(a)}(padded[map(Base.OneTo, a.shape)...])
end

Base.show(io::IO, a::PlainArrayPacked) = print(io, collect(a))

function Base.show(io::IO, ::MIME"text/plain", a::PlainArrayPacked)
    print(io, a.shape, "-shaped PlainArrayPacked{", backend_name(a), "} (padded to ",
          a.padded_shape, "):\n")
    Base.print_matrix(io, collect(a))
end

function Base.show(io::IO, ::MIME"text/plain", a::SecureArrayPacked)
    print(io, a.shape, "-shaped SecureArrayPacked{", backend_name(a), "} (padded to ",
          a.padded_shape, ")")
end

# Get wrapper name of a potentially parametric type
# Copied from: https://github.com/ClapeyronThermo/Clapeyron.jl/blob/f40c282e2236ff68d91f37c39b5c1e4230ae9ef0/src/utils/core_utils.jl#L17
# Original source: https://github.com/JuliaArrays/ArrayInterface.jl/blob/40d9a87be07ba323cca00f9e59e5285c13f7ee72/src/ArrayInterface.jl#L20
# Note: prefixed by `__` since it is really, really dirty black magic internals we use here!
__parameterless_type(T) = Base.typename(T).wrapper

# Convenience method for getting human-readable names
backend_name(x::Union{SecureContext{T}, SecureArray{T}, PlainArray{T}, PrivateKey{T},
                      PublicKey{T}, SecureArrayPacked{T},
                      PlainArrayPacked{T}}) where T = string(__parameterless_type(T))
