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
    lengths::Vector{Int}
    capacities::Vector{Int}
    context::SecureContext{CryptoBackendT}

    function SecureArray(data, shape, lengths, capacities,
                         context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, length(shape), typeof(data)}(data, shape, lengths, capacities, context)
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
    lengths::Vector{Int}
    capacities::Vector{Int}
    context::SecureContext{CryptoBackendT}

    function PlainArray(data, shape, lengths, capacities,
                        context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, length(shape), typeof(data)}(data, shape, lengths, capacities, context)
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
capacity(a::Union{PlainArray, SecureArray}) = sum(a.capacities)

# Get wrapper name of a potentially parametric type
# Copied from: https://github.com/ClapeyronThermo/Clapeyron.jl/blob/f40c282e2236ff68d91f37c39b5c1e4230ae9ef0/src/utils/core_utils.jl#L17
# Original source: https://github.com/JuliaArrays/ArrayInterface.jl/blob/40d9a87be07ba323cca00f9e59e5285c13f7ee72/src/ArrayInterface.jl#L20
# Note: prefixed by `__` since it is really, really dirty black magic internals we use here!
__parameterless_type(T) = Base.typename(T).wrapper

# Convenience method for getting human-readable names
backend_name(x::Union{SecureContext{T}, SecureArray{T}, PlainArray{T}, PrivateKey{T},
                      PublicKey{T}}) where T = string(__parameterless_type(T))
