var documenterSearchIndex = {"docs":
[{"location":"license/","page":"License","title":"License","text":"EditURL = \"https://github.com/hpsc-lab/SecureArithmetic.jl/blob/main/LICENSE.md\"","category":"page"},{"location":"license/#License","page":"License","title":"License","text":"","category":"section"},{"location":"license/","page":"License","title":"License","text":"MIT LicenseCopyright (c) 2023 Michael Schlottke-LakemperPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.","category":"page"},{"location":"reference/#API-reference","page":"API reference","title":"API reference","text":"","category":"section"},{"location":"reference/","page":"API reference","title":"API reference","text":"CurrentModule = SecureArithmetic","category":"page"},{"location":"reference/","page":"API reference","title":"API reference","text":"Modules = [SecureArithmetic]","category":"page"},{"location":"reference/#SecureArithmetic.OpenFHEBackend","page":"API reference","title":"SecureArithmetic.OpenFHEBackend","text":"OpenFHEBackend\n\nCryptography backend for use with the homomorphic encryption library OpenFHE (https://github.com/openfheorg/openfhe-development).\n\nSee also: SecureContext, Unencrypted\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainArray","page":"API reference","title":"SecureArithmetic.PlainArray","text":"PlainArray{Backend, N, DataT}\n\nHolds an encoded - but not encrypted - N-dimensional array for arithmetic operations. Can be converted to a SecureArray using encrypt.\n\nSee also: SecureArray, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainArray-Tuple{Array{<:Real}, SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.PlainArray","text":"PlainArray(data::Array{<:Real}, context::SecureContext{<:OpenFHEBackend})\n\nConstructor for data type PlainArray takes an unencrypted data array and a context object of type SecureContext{<:OpenFHEBackend}. Return PlainArray with encoded but not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureArray.\n\nSee also: PlainArray, SecureArray, encrypt, decrypt OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainArray-Tuple{Array{<:Real}, SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.PlainArray","text":"PlainArray(data::Array{<:Real}, context::SecureContext{<:Unencrypted})\n\nConstructor for data type PlainArray takes an unencrypted data array and a context object of type SecureContext{<:Unencrypted}. Returns PlainArray with not encoded and not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureArray.\n\nSee also: PlainArray, SecureArray, encrypt, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainMatrix","page":"API reference","title":"SecureArithmetic.PlainMatrix","text":"PlainMatrix{Backend, DataT}\n\nAlias for PlainArray{Backend, 2, DataT}. Holds encoded - but not encrypted - matrix data for arithmetic operations. Can be converted to a SecureMatrix using encrypt.\n\nSee also: SecureMatrix, PlainArray, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainMatrix-Tuple{Matrix{<:Real}, SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.PlainMatrix","text":"PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:OpenFHEBackend})\n\nConstructor for data type PlainMatrix takes an unencrypted data matrix and a context object of type SecureContext{<:OpenFHEBackend}. Return PlainMatrix with encoded but not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureMatrix.\n\nSee also: PlainMatrix, SecureMatrix, encrypt, decrypt OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainMatrix-Tuple{Matrix{<:Real}, SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.PlainMatrix","text":"PlainMatrix(data::Matrix{<:Real}, context::SecureContext{<:Unencrypted})\n\nConstructor for data type PlainMatrix takes an unencrypted data matrix and a context object of type SecureContext{<:Unencrypted}. Returns PlainMatrix with not encoded and not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureMatrix.\n\nSee also: PlainMatrix, SecureMatrix, encrypt, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainVector","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector{Backend, DataT}\n\nAlias for PlainArray{Backend, 1, DataT}. Holds encoded - but not encrypted - vector data for arithmetic operations. Can be converted to a SecureVector using encrypt.\n\nSee also: SecureVector, PlainArray, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainVector-Tuple{Vector{<:Real}, SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})\n\nConstructor for data type PlainVector takes an unencrypted data vector and a context object of type SecureContext{<:OpenFHEBackend}. Return PlainVector with encoded but not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureVector.\n\nSee also: PlainVector, SecureVector, encrypt, decrypt OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainVector-Tuple{Vector{<:Real}, SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector(data::Vector{<:Real}, context::SecureContext{<:Unencrypted})\n\nConstructor for data type PlainVector takes an unencrypted data vector and a context object of type SecureContext{<:Unencrypted}. Returns PlainVector with not encoded and not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureVector.\n\nSee also: PlainVector, SecureVector, encrypt, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PrivateKey","page":"API reference","title":"SecureArithmetic.PrivateKey","text":"PrivateKey\n\nHolds a private key that is used for decryption in decrypt.\n\nSee also: PlainVector, SecureVector, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PublicKey","page":"API reference","title":"SecureArithmetic.PublicKey","text":"PublicKey\n\nHolds a public key that is used for encryption in encrypt.\n\nSee also: PlainVector, SecureVector, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureArray","page":"API reference","title":"SecureArithmetic.SecureArray","text":"SecureArray{Backend, N, DataT}\n\nHolds an encrypted N-dimensional array for arithmetic operations. Can be converted to a PlainArray using decrypt.\n\nSee also: PlainArray, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureContext","page":"API reference","title":"SecureArithmetic.SecureContext","text":"SecureContext\n\nA structure used to generalize CryptoContext defined in OpenFHE.jl for unencrypted data, to maximize utilization of the same code for both plaintext and ciphertext.\n\nSee also: OpenFHEBackend, Unencrypted\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureMatrix","page":"API reference","title":"SecureArithmetic.SecureMatrix","text":"SecureMatrix{Backend, DataT}\n\nAlias for SecureArray{Backend, 2, DataT}. Holds encrypted matrix data for arithmetic operations. Can be converted to a PlainMatrix using decrypt.\n\nSee also: PlainMatrix, SecureArray, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureVector","page":"API reference","title":"SecureArithmetic.SecureVector","text":"SecureVector{Backend, DataT}\n\nAlias for SecureArray{Backend, 1, DataT}. Holds encrypted vector data for arithmetic operations. Can be converted to a PlainVector using decrypt.\n\nSee also: PlainVector, SecureArray, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.Unencrypted","page":"API reference","title":"SecureArithmetic.Unencrypted","text":"Unencrypted\n\nAn alternative backend to use instead of OpenFHEBackend to experiment with algorithms on unencrypted data.\n\nSee also: SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"type"},{"location":"reference/#Base.circshift-Tuple{SecureArray, Any}","page":"API reference","title":"Base.circshift","text":"circshift(sa::SecureArray, shifts)\n\nCircularly shift, i.e., rotate the data in sa by shifts positions, similarly to Julia's circshift for regular arrays.\n\nNote: If N is greater than one, this operation increases the multiplicative level by two, otherwise by one.\n\nNote: To precompute all required rotation indexes, use init_rotation!.\n\nSee also: SecureArray, init_rotation!\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.collect-Tuple{PlainArray{<:OpenFHEBackend}}","page":"API reference","title":"Base.collect","text":"collect(plain_array::PlainArray{<:OpenFHEBackend})\n\nDecode and return the real-valued data contained in plain_array.\n\nSee also: PlainArray, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.collect-Tuple{PlainArray{<:Unencrypted}}","page":"API reference","title":"Base.collect","text":"collect(pa::PlainArray{<:Unencrypted})\n\nReturn the real-valued data contained in pa.\n\nSee also: PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.length-Tuple{Union{PlainArray, SecureArray}}","page":"API reference","title":"Base.length","text":"length(a::Union{PlainArray, SecureArray})\n\nReturn the current length of a, i.e., the number of container elements in use. Note that this might be less than its maximum capacity.\n\nSee also: capacity, SecureArray, PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.ndims-Tuple{Union{PlainArray, SecureArray}}","page":"API reference","title":"Base.ndims","text":"ndims(a::Union{PlainArray, SecureArray})\n\nReturn the number of dimensions of a.\n\nSee also: SecureArray, PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.size-Tuple{Union{PlainArray, SecureArray}, Int64}","page":"API reference","title":"Base.size","text":"size(a::Union{PlainArray, SecureArray}, d::Int)\n\nReturn the current length of dth dimension of a.\n\nSee also: SecureArray, PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.size-Tuple{Union{PlainArray, SecureArray}}","page":"API reference","title":"Base.size","text":"size(a::Union{PlainArray, SecureArray})\n\nReturn the current shape of a.\n\nSee also: SecureArray, PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.bootstrap!","page":"API reference","title":"SecureArithmetic.bootstrap!","text":"bootstrap!(secure_array::SecureArray{<:Unencrypted}, num_iterations = 1,\n           precision = 0)\n\nAn empty duplicate of bootstrap! for unencrypted data.\n\nSee also: SecureArray, Unencrypted, bootstrap!, init_bootstrapping!\n\n\n\n\n\n","category":"function"},{"location":"reference/#SecureArithmetic.bootstrap!-2","page":"API reference","title":"SecureArithmetic.bootstrap!","text":"bootstrap!(secure_array::SecureArray{<:OpenFHEBackend}, num_iterations = 1,\n           precision = 0)\n\nRefresh a given secure_array to increase the multiplication depth. Supported for CKKS only. Please refer to the OpenFHE documentation for details on the arguments num_iterations and precision.\n\nSee also: SecureArray, OpenFHEBackend, init_bootstrapping!\n\n\n\n\n\n","category":"function"},{"location":"reference/#SecureArithmetic.capacity-Tuple{Union{PlainArray, SecureArray}}","page":"API reference","title":"SecureArithmetic.capacity","text":"capacity(a::Union{PlainArray, SecureArray})\n\nReturn the current capacity of a, i.e., the maximum number of elements the container may hold. Note that this might be more than its current length.\n\nSee also: length, SecureArray, PlainArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.decrypt!-Tuple{PlainArray, SecureArray, PrivateKey}","page":"API reference","title":"SecureArithmetic.decrypt!","text":"decrypt!(plain_array::PlainArray, secure_array::SecureArray, private_key::PrivateKey)\n\nDecrypt secure_array using the private_key and store the result in the given plain_array.\n\nSee also: PlainArray, SecureArray, PrivateKey, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.decrypt-Tuple{SecureArray, PrivateKey}","page":"API reference","title":"SecureArithmetic.decrypt","text":"decrypt(secure_array::SecureArray, private_key::PrivateKey)\n\nDecrypt secure_array using the private_key and return the resulting PlainArray.\n\nSee also: PlainArray, SecureArray, PrivateKey, decrypt!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.encrypt-Tuple{Array{<:Real}, PublicKey, SecureContext}","page":"API reference","title":"SecureArithmetic.encrypt","text":"encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)\n\nEncrypt data into a SecureArray using the public_key derived for the given context.\n\nSee also: SecureArray, PublicKey, SecureContext, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.encrypt-Tuple{PlainArray, PublicKey}","page":"API reference","title":"SecureArithmetic.encrypt","text":"encrypt(plain_array::PlainArray, public_key::PublicKey)\n\nEncrypt plain_array into a SecureArray using the public_key.\n\nSee also: PlainArray, SecureArray, PublicKey, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.generate_keys-Tuple{SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.generate_keys","text":"generate_keys(context::SecureContext{<:OpenFHEBackend})\n\nGenerate and return public and private keys.\n\nSee also: PublicKey, PrivateKey, SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.generate_keys-Tuple{SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.generate_keys","text":"generate_keys(context::SecureContext{<:Unencrypted})\n\nReturn public and private keys for use with unencrypted data.\n\nSee also: PublicKey, PrivateKey, SecureContext, Unencrypted\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.get_crypto_context-Tuple{SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.get_crypto_context","text":"get_crypto_context(context::SecureContext{<:OpenFHEBackend})\n\nReturn a OpenFHE.CryptoContext object stored in a given context.\n\nSee also: SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.get_crypto_context-Tuple{Union{PlainArray{<:OpenFHEBackend}, SecureArray{<:OpenFHEBackend}}}","page":"API reference","title":"SecureArithmetic.get_crypto_context","text":"get_crypto_context(a::Union{SecureArray{<:OpenFHEBackend},\n                            PlainArray{<:OpenFHEBackend}})\n\nReturn a OpenFHE.CryptoContext object stored in a.\n\nSee also: SecureContext, SecureArray, PlainArray, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_bootstrapping!-Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_bootstrapping!","text":"init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},\n                    private_key::PrivateKey)\n\nGenerate the necessary keys from private_key to enable bootstrapping for a given context. Supported for CKKS only.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey, bootstrap!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_bootstrapping!-Tuple{SecureContext{<:Unencrypted}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_bootstrapping!","text":"init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)\n\nAn empty duplicate of init_bootstrapping! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_bootstrapping!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_multiplication!-Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_multiplication!","text":"init_multiplication!(context::SecureContext{<:OpenFHEBackend},\n                     private_key::PrivateKey)\n\nGenerate relinearization key for use with OpenFHE.EvalMult using the private_key, and store it in the given context.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_multiplication!-Tuple{SecureContext{<:Unencrypted}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_multiplication!","text":"init_multiplication!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)\n\nAn empty duplicate of init_multiplication! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_multiplication!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_rotation!-Tuple{SecureContext{<:Unencrypted}, PrivateKey, Any, Vararg{Any}}","page":"API reference","title":"SecureArithmetic.init_rotation!","text":"init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey,\n               shape, shifts...)\n\nAn empty duplicate of init_rotation! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_rotation!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_rotation!-Union{Tuple{N}, Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey, Union{Integer, NTuple{N, Integer}}, Vararg{Any}}} where N","page":"API reference","title":"SecureArithmetic.init_rotation!","text":"init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,\n               shape::Union{Integer, NTuple{N, Integer}}, shifts...)\n\nGenerate all required rotation keys for applying shifts with circshift for arrays of the given shape using the private_key. The keys are stored in the given context.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.level-Tuple{Union{PlainArray{<:OpenFHEBackend}, SecureArray{<:OpenFHEBackend}}}","page":"API reference","title":"SecureArithmetic.level","text":"level(a::Union{SecureArray{<:OpenFHEBackend}, PlainArray{<:OpenFHEBackend}})\n\nReturn the number of scalings, referred to as the level, performed over a.\n\nSee also: PlainArray, SecureArray, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.level-Tuple{Union{PlainArray{<:Unencrypted}, SecureArray{<:Unencrypted}}}","page":"API reference","title":"SecureArithmetic.level","text":"level(a::Union{SecureArray{<:Unencrypted}, PlainArray{<:Unencrypted}})\n\nReturn the number of scalings, referred to as the level, performed over a. For data type derived from Unencrypted, the level is always equal to 0.\n\nSee also: PlainArray, SecureArray\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.release_context_memory-Tuple{}","page":"API reference","title":"SecureArithmetic.release_context_memory","text":"release_context_memory()\n\nRelease all OpenFHE.CryptoContexts and keys for multiplication, rotation, bootstrapping and OpenFHE.EvalSum generated in the functions init_multiplication!, init_rotation!, init_bootstrapping! and OpenFHE.EvalSumKeyGen.\n\nIn the source code of OpenFHE C++, all CryptoContexts and keys are stored in static objects. Without using release_context_memory, the memory allocated for these contexts and keys will only be freed after restarting the Julia REPL. It is also advisable to call GC.gc() after a call to release_context_memory to clean up all memory on the Julia side.\n\nSee also: init_multiplication!, init_rotation!, init_bootstrapping!\n\n\n\n\n\n","category":"method"},{"location":"","page":"Home","title":"Home","text":"EditURL = \"https://github.com/hpsc-lab/SecureArithmetic.jl/blob/main/README.md\"","category":"page"},{"location":"#SecureArithmetic.jl","page":"Home","title":"SecureArithmetic.jl","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"(Image: Docs-stable) (Image: Docs-dev) (Image: Build Status) (Image: Coveralls) (Image: Codecov) (Image: License: MIT) (Image: DOI)","category":"page"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl is a Julia package for performing cryptographically secure arithmetic operations using fully homomorphic encryption. It currently provides a backend for OpenFHE-secured computations using OpenFHE.jl, and an unencrypted backend for fast verification of a computation pipeline.","category":"page"},{"location":"#Getting-started","page":"Home","title":"Getting started","text":"","category":"section"},{"location":"#Prerequisites","page":"Home","title":"Prerequisites","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"If you have not yet installed Julia, please follow the instructions for your operating system. SecureArithmetic.jl works with Julia v1.8 and later on Linux and macOS platforms, and with Julia v1.9 or later on Windows platforms.","category":"page"},{"location":"#Installation","page":"Home","title":"Installation","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"Since SecureArithmetic.jl  is a registered Julia package, you can install it by executing the following commands in the Julia REPL:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> import Pkg; Pkg.add(\"SecureArithmetic\")","category":"page"},{"location":"","page":"Home","title":"Home","text":"If you plan on running the examples in the examples directory, you also need to install OpenFHE.jl:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> import Pkg; Pkg.add(\"OpenFHE\")","category":"page"},{"location":"#Usage","page":"Home","title":"Usage","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"The easiest way to get started is to run one of the examples from the examples directory by includeing them in Julia, e.g.,","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> using SecureArithmetic\n\njulia> include(joinpath(pkgdir(SecureArithmetic), \"examples\", \"simple_real_numbers.jl\"))\n================================================================================\nCreating OpenFHE context...\nCKKS scheme is using ring dimension 16384\n\n================================================================================\nCreating unencrypted context...\n\n================================================================================\nsimple_real_numbers with an OpenFHE context\nInput x1: [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nInput x2: [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]\n\nResults of homomorphic computations:\nx1 = [0.24999999999993638, 0.500000000000056, 0.7500000000000366, 0.9999999999999498, 2.0000000000000333, 3.0000000000000675, 3.9999999999999902, 4.99999999999997]\nx1 + x2 = [5.2499999999999485, 4.499999999999966, 3.7500000000000533, 3.0000000000000466, 3.000000000000019, 3.7499999999999836, 4.499999999999986, 5.249999999999975]\nx1 - x2 = [-4.749999999999893, -3.4999999999999805, -2.249999999999964, -0.9999999999998668, 0.9999999999999534, 2.249999999999984, 3.5000000000000973, 4.749999999999956]\n4 * x1 = [1.0000000000004539, 1.9999999999998535, 3.000000000000176, 4.000000000000274, 7.999999999998697, 12.000000000000373, 15.999999999998332, 20.00000000000011]\nx1 * x2 = [1.2500000000002318, 2.000000000000054, 2.2499999999994893, 1.9999999999998272, 2.000000000000205, 2.25000000000003, 1.9999999999997906, 1.2499999999996558]\nx1 shifted circularly by -1 = [0.4999999999998632, 0.749999999999976, 0.9999999999999369, 1.9999999999999858, 2.9999999999998677, 4.000000000000045, 5.000000000000059, 0.25000000000002087]\nx1 shifted circularly by 2 = [3.9999999999999973, 4.99999999999995, 0.2499999999999567, 0.49999999999996825, 0.7500000000000793, 0.9999999999998956, 2.00000000000004, 2.999999999999985]\n\n================================================================================\nsimple_real_numbers with an Unencrypted context\nInput x1: [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nInput x2: [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]\n\nResults of homomorphic computations:\nx1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nx1 + x2 = [5.25, 4.5, 3.75, 3.0, 3.0, 3.75, 4.5, 5.25]\nx1 - x2 = [-4.75, -3.5, -2.25, -1.0, 1.0, 2.25, 3.5, 4.75]\n4 * x1 = [1.0, 2.0, 3.0, 4.0, 8.0, 12.0, 16.0, 20.0]\nx1 * x2 = [1.25, 2.0, 2.25, 2.0, 2.0, 2.25, 2.0, 1.25]\nx1 shifted circularly by -1 = [0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0, 0.25]\nx1 shifted circularly by 2 = [4.0, 5.0, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0]","category":"page"},{"location":"#Memory-issues","page":"Home","title":"Memory issues","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"OpenFHE is a memory-optimized C++ library, but these optimizations can cause memory issues when transitioning to Julia.","category":"page"},{"location":"","page":"Home","title":"Home","text":"In OpenFHE, large objects like Ciphertext, Plaintext, and CryptoContext are managed using std::shared_ptr. These objects are not freed until all associated std::shared_ptrs are destroyed. Since the Julia objects that hold a reference to these shared pointers are relatively small, Julia's garbage collector does not always free them automatically, as they are not considered a high priority for garbage collection. This is because Julia's garbage collector primarily focuses on \"young\" objects during its incremental collections, leaving some std::shared_ptrs in memory even when they are no longer in use. This may result in a significant increase in memory consumption over time, as a single Ciphertext object can occupy over 60 MB. Consequently, complex operations may lead to gigabytes of memory being occupied without being freed until the Julia session is terminated. One possible solution is to manually trigger Julia's garbage collector to perform a full collection, which will also clean up these \"small\" objects:","category":"page"},{"location":"","page":"Home","title":"Home","text":"GC.gc()","category":"page"},{"location":"","page":"Home","title":"Home","text":"Additionally, OpenFHE optimizes memory usage in C++ by storing evaluation keys and CryptoContexts in static objects. These objects, being quite large, remain in memory until the Julia REPL is closed. To release them while the REPL is still running, you can execute the following function:","category":"page"},{"location":"","page":"Home","title":"Home","text":"release_context_memory()","category":"page"},{"location":"","page":"Home","title":"Home","text":"Note that this will invalidate all currently existing contexts, even those which are still in use. Thus you should only call these functions once you are done with a given FHE setup and want to start a new one. For more details, please refer to the documentation for release_context_memory.","category":"page"},{"location":"","page":"Home","title":"Home","text":"Therefore, for a full cleanup of all OpenFHE-occupied memory, first ensure that all variables holding references to OpenFHE objects are out of scope and then execute","category":"page"},{"location":"","page":"Home","title":"Home","text":"release_context_memory()\nGC.gc()","category":"page"},{"location":"","page":"Home","title":"Home","text":"By running these commands at appropriate points in your code, you can prevent excessive memory usage and ensure efficient memory management when using SecureArithmetic.jl.","category":"page"},{"location":"#Referencing","page":"Home","title":"Referencing","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"If you use SecureArithmetic.jl in your own research, please cite this repository as follows:","category":"page"},{"location":"","page":"Home","title":"Home","text":"@misc{schlottkelakemper2024securearithmetic,\n  title={{S}ecure{A}rithmetic.jl: {S}ecure arithmetic operations in {J}ulia using fully homomorphic encryption},\n  author={Schlottke-Lakemper, Michael},\n  year={2024},\n  howpublished={\\url{https://github.com/hpsc-lab/SecureArithmetic.jl}},\n  doi={10.5281/zenodo.10544790}\n}","category":"page"},{"location":"#Authors","page":"Home","title":"Authors","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl was initiated by Michael Schlottke-Lakemper (University of Augsburg, Germany), who is also its principal maintainer.","category":"page"},{"location":"#License-and-contributing","page":"Home","title":"License and contributing","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl is available under the MIT license (see License). Contributions by the community are very welcome! For larger proposed changes, feel free to reach out via an issue first.","category":"page"}]
}
