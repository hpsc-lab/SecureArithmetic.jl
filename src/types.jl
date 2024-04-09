abstract type AbstractCryptoBackend end

struct SecureContext{CryptoBackendT <: AbstractCryptoBackend}
    backend::CryptoBackendT
end

function Base.show(io::IO, v::SecureContext)
    print("SecureContext{", backend_name(v), "}()")
end

"""
    SecureVector

Holds encrypted data for arithmetic operations. Can be converted to a `PlainVector` using
[`decrypt`](@ref).

See also: [`PlainVector`](@ref), [`decrypt`](@ref)
"""
mutable struct SecureVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    length::Int
    capacity::Int
    context::SecureContext{CryptoBackendT}

    function SecureVector(data, length, capacity, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, length, capacity, context)
    end
end

function Base.show(io::IO, v::SecureVector)
    print("SecureVector{", backend_name(v), "}(data=<encrypted>, length=$(v.length))")
end

"""
    PlainVector

Holds encoded - but not encrypted - data for arithmetic operations. Can be converted to a
`SecureVector` using [`encrypt`](@ref).

See also: [`SecureVector`](@ref), [`encrypt`](@ref)
"""
struct PlainVector{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::DataT
    length::Int
    capacity::Int
    context::SecureContext{CryptoBackendT}

    function PlainVector(data, length, capacity, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data)}(data, length, capacity, context)
    end
end

"""
    length(v::Union{PlainVector, SecureVector})

Return the current length of `v`, i.e., the number of container elements in use.
Note that this might be less than its maximum [`capacity`](@ref).

See also: [`capacity`](@ref), [`SecureVector`](@ref), [`PlainVector`](@ref)
"""
Base.length(v::Union{PlainVector, SecureVector}) = v.length

"""
    capacity(v::Union{PlainVector, SecureVector})

Return the current capacity of `v`, i.e., the maximum number of elements the container may
hold.. Note that this might be more than its current [`length`](@ref).

See also: [`length`](@ref), [`SecureVector`](@ref), [`PlainVector`](@ref)
"""
capacity(v::Union{PlainVector, SecureVector}) = v.capacity

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

# Get wrapper name of a potentially parametric type
# Copied from: https://github.com/ClapeyronThermo/Clapeyron.jl/blob/f40c282e2236ff68d91f37c39b5c1e4230ae9ef0/src/utils/core_utils.jl#L17
# Original source: https://github.com/JuliaArrays/ArrayInterface.jl/blob/40d9a87be07ba323cca00f9e59e5285c13f7ee72/src/ArrayInterface.jl#L20
# Note: prefixed by `__` since it is really, really dirty black magic internals we use here!
__parameterless_type(T) = Base.typename(T).wrapper

# Convenience method for getting human-readable names
backend_name(x::Union{SecureContext{T}, SecureVector{T}, PlainVector{T}, PrivateKey{T},
                      PublicKey{T}}) where T = string(__parameterless_type(T))

struct PlainMatrix{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::Vector{PlainVector{CryptoBackendT, DataT}}
    length::Int
    context::SecureContext{CryptoBackendT}

    function PlainMatrix(data, length, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data[1])}(data, length, context)
    end
end

struct SecureMatrix{CryptoBackendT <: AbstractCryptoBackend, DataT}
    data::Vector{SecureVector{CryptoBackendT, DataT}}
    length::Int
    context::SecureContext{CryptoBackendT}

    function SecureMatrix(data, length, context::SecureContext{CryptoBackendT}) where CryptoBackendT
        new{CryptoBackendT, typeof(data[1])}(data, length, context)
    end
end

Base.length(v::Union{PlainMatrix, SecureMatrix}) = v.length