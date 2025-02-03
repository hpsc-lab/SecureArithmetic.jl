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
