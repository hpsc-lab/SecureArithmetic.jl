"""
    encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)

Encrypt `data` into a [`SecureArray`](@ref) using the `public_key` derived for the given
`context`.

See also: [`SecureArray`](@ref), [`PublicKey`](@ref), [`SecureContext`](@ref), [`decrypt`](@ref)
"""
function encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end

"""
    encrypt(plain_array::PlainArray, public_key::PublicKey)

Encrypt `plain_array` into a [`SecureArray`](@ref) using the `public_key`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PublicKey`](@ref), [`decrypt`](@ref)
"""
function encrypt(plain_array::PlainArray, public_key::PublicKey)
    encrypt_impl(plain_array, public_key)
end

"""
    decrypt!(plain_array::PlainArray, secure_array::SecureArray, private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and store the result in the given
`plain_array`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PrivateKey`](@ref), [`decrypt`](@ref)
"""
function decrypt!(plain_array::PlainArray, secure_array::SecureArray,
                  private_key::PrivateKey)
    decrypt_impl!(plain_array, secure_array, private_key)
end

"""
    decrypt(secure_array::SecureArray, private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and return the resulting `PlainArray`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PrivateKey`](@ref), [`decrypt!`](@ref)
"""
function decrypt(secure_array::SecureArray, private_key::PrivateKey)
    decrypt_impl(secure_array, private_key)
end

"""
    serialize(obj)

Serialize `obj` to a JSON string.

See also: [`deserialize`](@ref)
"""
function serialize(obj)
    # Convert from C++ string to Julia String for memory safety
    String(OpenFHE.SerializeToString(obj))
end

"""
    deserialize(::Type{T}, json::AbstractString)

Deserialize a JSON string `json` into a new object of type `T`.

See also: [`serialize`](@ref)
"""
function deserialize(::Type{T}, json::AbstractString) where T
    obj = T()
    OpenFHE.DeserializeFromString(obj, json)
    return obj
end

"""
    serialize_to_binary_file(filename::AbstractString, obj)

Serialize `obj` to a binary file at `filename`.
Returns `true` if the file was written successfully, `false` otherwise.

See also: [`deserialize_from_binary_file`](@ref), [`serialize_to_json_file`](@ref)
"""
function serialize_to_binary_file(filename::AbstractString, obj)
    OpenFHE.SerializeToFile(filename, obj, OpenFHE.SERBINARY())
end

"""
    serialize_to_json_file(filename::AbstractString, obj)

Serialize `obj` to a JSON file at `filename`.
Returns `true` if the file was written successfully, `false` otherwise.

See also: [`deserialize_from_json_file`](@ref), [`serialize_to_binary_file`](@ref)
"""
function serialize_to_json_file(filename::AbstractString, obj)
    OpenFHE.SerializeToFile(filename, obj, OpenFHE.SERJSON())
end

"""
    deserialize_from_binary_file(::Type{T}, filename::AbstractString)

Deserialize from a binary file at `filename` into a new object of type `T`.

See also: [`serialize_to_binary_file`](@ref), [`deserialize_from_json_file`](@ref)
"""
function deserialize_from_binary_file(::Type{T}, filename::AbstractString) where T
    obj = T()
    OpenFHE.DeserializeFromFile(filename, obj, OpenFHE.SERBINARY())
    return obj
end

"""
    deserialize_from_json_file(::Type{T}, filename::AbstractString)

Deserialize from a JSON file at `filename` into a new object of type `T`.

See also: [`serialize_to_json_file`](@ref), [`deserialize_from_binary_file`](@ref)
"""
function deserialize_from_json_file(::Type{T}, filename::AbstractString) where T
    obj = T()
    OpenFHE.DeserializeFromFile(filename, obj, OpenFHE.SERJSON())
    return obj
end

"""
    release_context_memory()

Release all `OpenFHE.CryptoContext`s and keys for multiplication, rotation, bootstrapping and
`OpenFHE.EvalSum` generated in the functions [`init_multiplication!`](@ref),
[`init_rotation!`](@ref), [`init_bootstrapping!`](@ref) and `OpenFHE.EvalSumKeyGen`.

In the source code of OpenFHE C++, all `CryptoContext`s and keys are stored in static objects.
Without using `release_context_memory`, the memory allocated for these contexts and keys will
only be freed after restarting the Julia REPL. It is also advisable to call `GC.gc()` after
a call to `release_context_memory` to clean up all memory on the Julia side.

See also: [`init_multiplication!`](@ref), [`init_rotation!`](@ref), [`init_bootstrapping!`](@ref)
"""
function release_context_memory()
    OpenFHE.ClearEvalMultKeys()
    OpenFHE.ClearEvalSumKeys()
    OpenFHE.ClearEvalAutomorphismKeys()
    OpenFHE.ReleaseAllContexts()
    
    nothing
end
