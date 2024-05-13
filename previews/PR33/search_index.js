var documenterSearchIndex = {"docs":
[{"location":"license/","page":"License","title":"License","text":"EditURL = \"https://github.com/sloede/SecureArithmetic/blob/main/LICENSE.md\"","category":"page"},{"location":"license/#License","page":"License","title":"License","text":"","category":"section"},{"location":"license/","page":"License","title":"License","text":"MIT LicenseCopyright (c) 2023 Michael Schlottke-LakemperPermission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the \"Software\"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.","category":"page"},{"location":"reference/#API-reference","page":"API reference","title":"API reference","text":"","category":"section"},{"location":"reference/","page":"API reference","title":"API reference","text":"CurrentModule = SecureArithmetic","category":"page"},{"location":"reference/","page":"API reference","title":"API reference","text":"Modules = [SecureArithmetic]","category":"page"},{"location":"reference/#SecureArithmetic.OpenFHEBackend","page":"API reference","title":"SecureArithmetic.OpenFHEBackend","text":"OpenFHEBackend\n\nCryptography backend for use with the homomorphic encryption library OpenFHE (https://github.com/openfheorg/openfhe-development).\n\nSee also: SecureContext, Unencrypted\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainVector","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector\n\nHolds encoded - but not encrypted - data for arithmetic operations. Can be converted to a SecureVector using encrypt.\n\nSee also: SecureVector, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PlainVector-Tuple{Vector{<:Real}, SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector(data::Vector{<:Real}, context::SecureContext{<:OpenFHEBackend})\n\nConstructor for data type PlainVector takes an unencrypted data vector and a context object of type SecureContext{<:OpenFHEBackend}. Return PlainVector with encoded but not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureVector.\n\nSee also: PlainVector, SecureVector, encrypt, decrypt OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainVector-Tuple{Vector{<:Real}, SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector(data::Vector{<:Real}, context::SecureContext{<:Unencrypted})\n\nConstructor for data type PlainVector takes an unencrypted data vector and a context object of type SecureContext{<:Unencrypted}. Returns PlainVector with not encoded and not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureVector.\n\nSee also: PlainVector, SecureVector, encrypt, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PlainVector-Tuple{Vector{Float64}, SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.PlainVector","text":"PlainVector(data::Vector{Float64}, context::SecureContext{<:OpenFHEBackend})\n\nConstructor for data type PlainVector takes an unencrypted data vector and a context object of type SecureContext{<:OpenFHEBackend}. Return PlainVector with encoded but not encrypted data. The context can be utilized later for encryption using encrypt, resulting in SecureVector.\n\nSee also: PlainVector, SecureVector, encrypt, decrypt OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.PrivateKey","page":"API reference","title":"SecureArithmetic.PrivateKey","text":"PrivateKey\n\nHolds a private key that is used for decryption in decrypt.\n\nSee also: PlainVector, SecureVector, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.PublicKey","page":"API reference","title":"SecureArithmetic.PublicKey","text":"PublicKey\n\nHolds a public key that is used for encryption in encrypt.\n\nSee also: PlainVector, SecureVector, encrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureContext","page":"API reference","title":"SecureArithmetic.SecureContext","text":"SecureContext\n\nA structure used to generalize CryptoContext defined in OpenFHE.jl for unencrypted data, to maximize utilization of the same code for both plaintext and ciphertext.\n\nSee also: OpenFHEBackend, Unencrypted\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.SecureVector","page":"API reference","title":"SecureArithmetic.SecureVector","text":"SecureVector\n\nHolds encrypted data for arithmetic operations. Can be converted to a PlainVector using decrypt.\n\nSee also: PlainVector, decrypt\n\n\n\n\n\n","category":"type"},{"location":"reference/#SecureArithmetic.Unencrypted","page":"API reference","title":"SecureArithmetic.Unencrypted","text":"Unencrypted\n\nAn alternative backend to use instead of OpenFHEBackend to experiment with algorithms on unencrypted data.\n\nSee also: SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"type"},{"location":"reference/#Base.circshift-Tuple{SecureVector, Integer}","page":"API reference","title":"Base.circshift","text":"circshift(sv::SecureVector, shift; wrap_by = :capacity)\n\nCircularly shift, i.e., rotate the data in sv by shift positions, similarly to Julia's circshift for regular arrays. wrap_by indicates whether the rotation should be applied with respect to the current data length of sv (wrap_by :length) or with respect to its maximum capacity (wrap_by = :capacity).\n\nNote: If sv's length is less than its capacity, wrapping by :length increases the multiplicative depth of your algorithm by one and is more expensive to compute. Furthermore, one additional rotation is applied with a shift of -sign(shift) * (length(sv) - abs(shift)).\n\nSee also: SecureVector, length, capacity\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.collect-Tuple{PlainVector{<:OpenFHEBackend}}","page":"API reference","title":"Base.collect","text":"collect(v::PlainVector{<:OpenFHEBackend})\n\nDecode and return the real-valued data contained in v.\n\nSee also: PlainVector, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.collect-Tuple{PlainVector{<:Unencrypted}}","page":"API reference","title":"Base.collect","text":"collect(v::PlainVector{<:Unencrypted})\n\nReturn the real-valued data contained in v.\n\nSee also: PlainVector\n\n\n\n\n\n","category":"method"},{"location":"reference/#Base.length-Tuple{Union{PlainVector, SecureVector}}","page":"API reference","title":"Base.length","text":"length(v::Union{PlainVector, SecureVector})\n\nReturn the current length of v, i.e., the number of container elements in use. Note that this might be less than its maximum capacity.\n\nSee also: capacity, SecureVector, PlainVector\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.bootstrap!-Tuple{SecureVector{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.bootstrap!","text":"bootstrap!(secure_vector::SecureVector{<:OpenFHEBackend})\n\nRefresh a given secure_vector to increase the multiplication depth. Supported for CKKS only.\n\nSee also: SecureVector, OpenFHEBackend, init_bootstrapping!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.bootstrap!-Tuple{SecureVector{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.bootstrap!","text":"bootstrap!(secure_vector::SecureVector{<:Unencrypted})\n\nAn empty duplicate of bootstrap! for unencrypted data.\n\nSee also: SecureVector, Unencrypted, bootstrap!, init_bootstrapping!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.capacity-Tuple{Union{PlainVector, SecureVector}}","page":"API reference","title":"SecureArithmetic.capacity","text":"capacity(v::Union{PlainVector, SecureVector})\n\nReturn the current capacity of v, i.e., the maximum number of elements the container may hold.. Note that this might be more than its current length.\n\nSee also: length, SecureVector, PlainVector\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.decrypt!-Tuple{PlainVector, SecureVector, PrivateKey}","page":"API reference","title":"SecureArithmetic.decrypt!","text":"decrypt!(plain_vector::PlainVector, secure_vector::SecureVector, private_key::PrivateKey)\n\nDecrypt secure_vector using the private_key and store the result in the given plain_text.\n\nSee also: PlainVector, SecureVector, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.decrypt-Tuple{SecureVector, PrivateKey}","page":"API reference","title":"SecureArithmetic.decrypt","text":"decrypt(secure_vector::SecureVector, private_key::PrivateKey)\n\nDecrypt secure_vector using the private_key and return the resulting PlainVector.\n\nSee also: PlainVector, SecureVector, decrypt!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.encrypt-Tuple{PlainVector, PublicKey}","page":"API reference","title":"SecureArithmetic.encrypt","text":"encrypt(plain_vector::PlainVector, public_key::PublicKey)\n\nEncrypt plain_vector into a SecureVector using the public_key.\n\nSee also: PlainVector, SecureVector, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.encrypt-Tuple{Vector{<:Real}, PublicKey, SecureContext}","page":"API reference","title":"SecureArithmetic.encrypt","text":"encrypt(data::Vector{<:Real}, public_key::PublicKey, context::SecureContext)\n\nEncrypt data into a SecureVector using the public_key derived for the given context.\n\nSee also: SecureVector, decrypt\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.generate_keys-Tuple{SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.generate_keys","text":"generate_keys(context::SecureContext{<:OpenFHEBackend})\n\nGenerate and return public and private keys.\n\nSee also: PublicKey, PrivateKey, SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.generate_keys-Tuple{SecureContext{<:Unencrypted}}","page":"API reference","title":"SecureArithmetic.generate_keys","text":"generate_keys(context::SecureContext{<:Unencrypted})\n\nReturn public and private keys for use with unencrypted data.\n\nSee also: PublicKey, PrivateKey, SecureContext, Unencrypted\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.get_crypto_context-Tuple{SecureContext{<:OpenFHEBackend}}","page":"API reference","title":"SecureArithmetic.get_crypto_context","text":"get_crypto_context(context::SecureContext{<:OpenFHEBackend})\n\nReturn a OpenFHE.CryptoContext object stored in a given context.\n\nSee also: SecureContext, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.get_crypto_context-Tuple{Union{PlainVector{<:OpenFHEBackend}, SecureVector{<:OpenFHEBackend}}}","page":"API reference","title":"SecureArithmetic.get_crypto_context","text":"get_crypto_context(v::Union{SecureVector{<:OpenFHEBackend},\n                            PlainVector{<:OpenFHEBackend}})\n\nReturn a OpenFHE.CryptoContext object stored in v.\n\nSee also: SecureContext, SecureVector, PlainVector, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_bootstrapping!-Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_bootstrapping!","text":"init_bootstrapping!(context::SecureContext{<:OpenFHEBackend},\n                    private_key::PrivateKey)\n\nGenerate the necessary keys from private_key to enable bootstrapping for a given context. Supported for CKKS only.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey, bootstrap!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_bootstrapping!-Tuple{SecureContext{<:Unencrypted}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_bootstrapping!","text":"init_bootstrapping!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)\n\nAn empty duplicate of init_bootstrapping! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_bootstrapping!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_multiplication!-Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_multiplication!","text":"init_multiplication!(context::SecureContext{<:OpenFHEBackend},\n                     private_key::PrivateKey)\n\nGenerate relinearization key for use with OpenFHE.EvalMult using the private_key, and store it in the given context.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_multiplication!-Tuple{SecureContext{<:Unencrypted}, PrivateKey}","page":"API reference","title":"SecureArithmetic.init_multiplication!","text":"init_multiplication!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey)\n\nAn empty duplicate of init_multiplication! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_multiplication!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_rotation!-Tuple{SecureContext{<:OpenFHEBackend}, PrivateKey, Any}","page":"API reference","title":"SecureArithmetic.init_rotation!","text":"init_rotation!(context::SecureContext{<:OpenFHEBackend}, private_key::PrivateKey,\n               shifts)\n\nGenerate rotation keys for use with OpenFHE.EvalRotate using the private_key and for the rotation indexes in shifts. The keys are stored in the given context. Positive shift defines rotation to the right, e.g. a rotation with a shift 1: [1, 2, 3, 4] -> [4, 1, 2, 3]. Negative shift defines rotation to the left, e.g. a rotation with a shift -1: [1, 2, 3, 4] -> [2, 3, 4, 1].\n\nNote: Here, indexes stored in shifts have reversed sign compared to rotation indexes used in OpenFHE.\n\nSee also: SecureContext, OpenFHEBackend, PrivateKey\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.init_rotation!-Tuple{SecureContext{<:Unencrypted}, PrivateKey, Any}","page":"API reference","title":"SecureArithmetic.init_rotation!","text":"init_rotation!(context::SecureContext{<:Unencrypted}, private_key::PrivateKey, shifts)\n\nAn empty duplicate of init_rotation! for unencrypted data.\n\nSee also: SecureContext, Unencrypted, PrivateKey, init_rotation!\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.level-Tuple{Union{PlainVector{<:OpenFHEBackend}, SecureVector{<:OpenFHEBackend}}}","page":"API reference","title":"SecureArithmetic.level","text":"level(v::Union{SecureVector{<:OpenFHEBackend}, PlainVector{<:OpenFHEBackend}})\n\nReturn the number of scalings, referred to as the level, performed over v.\n\nSee also: PlainVector, SecureVector, OpenFHEBackend\n\n\n\n\n\n","category":"method"},{"location":"reference/#SecureArithmetic.level-Tuple{Union{PlainVector{<:Unencrypted}, SecureVector{<:Unencrypted}}}","page":"API reference","title":"SecureArithmetic.level","text":"level(v::Union{SecureVector{<:Unencrypted}, PlainVector{<:Unencrypted}})\n\nReturn the number of scalings, referred to as the level, performed over v. For data type derived from Unencrypted, the level is always equal to 0.\n\nSee also: PlainVector, SecureVector\n\n\n\n\n\n","category":"method"},{"location":"","page":"Home","title":"Home","text":"EditURL = \"https://github.com/sloede/SecureArithmetic.jl/blob/main/README.md\"","category":"page"},{"location":"#SecureArithmetic.jl","page":"Home","title":"SecureArithmetic.jl","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"(Image: Docs-stable) (Image: Docs-dev) (Image: Build Status) (Image: Coveralls) (Image: Codecov) (Image: License: MIT) (Image: DOI)","category":"page"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl is a Julia package for performing cryptographically secure arithmetic operations using fully homomorphic encryption. It currently provides a backend for OpenFHE-secured computations using OpenFHE.jl, and an unencrypted backend for fast verification of a computation pipeline.","category":"page"},{"location":"#Getting-started","page":"Home","title":"Getting started","text":"","category":"section"},{"location":"#Prerequisites","page":"Home","title":"Prerequisites","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"If you have not yet installed Julia, please follow the instructions for your operating system. SecureArithmetic.jl works with Julia v1.8 and later on Linux and macOS platforms, and with Julia v1.9 or later on Windows platforms.","category":"page"},{"location":"#Installation","page":"Home","title":"Installation","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"Since SecureArithmetic.jl  is a registered Julia package, you can install it by executing the following commands in the Julia REPL:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> import Pkg; Pkg.add(\"SecureArithmetic\")","category":"page"},{"location":"","page":"Home","title":"Home","text":"If you plan on running the examples in the examples directory, you also need to install OpenFHE.jl:","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> import Pkg; Pkg.add(\"OpenFHE\")","category":"page"},{"location":"#Usage","page":"Home","title":"Usage","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"The easiest way to get started is to run one of the examples from the examples directory by includeing them in Julia, e.g.,","category":"page"},{"location":"","page":"Home","title":"Home","text":"julia> using SecureArithmetic\n\njulia> include(joinpath(pkgdir(SecureArithmetic), \"examples\", \"simple_real_numbers.jl\"))\n================================================================================\nCreating OpenFHE context...\nCKKS scheme is using ring dimension 16384\n\n================================================================================\nCreating unencrypted context...\n\n================================================================================\nsimple_real_numbers with an OpenFHE context\nInput x1: [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nInput x2: [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]\n\nResults of homomorphic computations:\nx1 = [0.24999999999993638, 0.500000000000056, 0.7500000000000366, 0.9999999999999498, 2.0000000000000333, 3.0000000000000675, 3.9999999999999902, 4.99999999999997]\nx1 + x2 = [5.2499999999999485, 4.499999999999966, 3.7500000000000533, 3.0000000000000466, 3.000000000000019, 3.7499999999999836, 4.499999999999986, 5.249999999999975]\nx1 - x2 = [-4.749999999999893, -3.4999999999999805, -2.249999999999964, -0.9999999999998668, 0.9999999999999534, 2.249999999999984, 3.5000000000000973, 4.749999999999956]\n4 * x1 = [1.0000000000004539, 1.9999999999998535, 3.000000000000176, 4.000000000000274, 7.999999999998697, 12.000000000000373, 15.999999999998332, 20.00000000000011]\nx1 * x2 = [1.2500000000002318, 2.000000000000054, 2.2499999999994893, 1.9999999999998272, 2.000000000000205, 2.25000000000003, 1.9999999999997906, 1.2499999999996558]\nx1 shifted circularly by -1 = [0.4999999999998632, 0.749999999999976, 0.9999999999999369, 1.9999999999999858, 2.9999999999998677, 4.000000000000045, 5.000000000000059, 0.25000000000002087]\nx1 shifted circularly by 2 = [3.9999999999999973, 4.99999999999995, 0.2499999999999567, 0.49999999999996825, 0.7500000000000793, 0.9999999999998956, 2.00000000000004, 2.999999999999985]\n\n================================================================================\nsimple_real_numbers with an Unencrypted context\nInput x1: [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nInput x2: [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]\n\nResults of homomorphic computations:\nx1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]\nx1 + x2 = [5.25, 4.5, 3.75, 3.0, 3.0, 3.75, 4.5, 5.25]\nx1 - x2 = [-4.75, -3.5, -2.25, -1.0, 1.0, 2.25, 3.5, 4.75]\n4 * x1 = [1.0, 2.0, 3.0, 4.0, 8.0, 12.0, 16.0, 20.0]\nx1 * x2 = [1.25, 2.0, 2.25, 2.0, 2.0, 2.25, 2.0, 1.25]\nx1 shifted circularly by -1 = [0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0, 0.25]\nx1 shifted circularly by 2 = [4.0, 5.0, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0]","category":"page"},{"location":"#Referencing","page":"Home","title":"Referencing","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"If you use SecureArithmetic.jl in your own research, please cite this repository as follows:","category":"page"},{"location":"","page":"Home","title":"Home","text":"@misc{schlottkelakemper2024securearithmetic,\n  title={{S}ecure{A}rithmetic.jl: {S}ecure arithmetic operations in {J}ulia using fully homomorphic encryption},\n  author={Schlottke-Lakemper, Michael},\n  year={2024},\n  howpublished={\\url{https://github.com/sloede/SecureArithmetic.jl}},\n  doi={10.5281/zenodo.10544790}\n}","category":"page"},{"location":"#Authors","page":"Home","title":"Authors","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl was initiated by Michael Schlottke-Lakemper (RWTH Aachen University/High-Performance Computing Center Stuttgart (HLRS), Germany), who is also its principal maintainer.","category":"page"},{"location":"#License-and-contributing","page":"Home","title":"License and contributing","text":"","category":"section"},{"location":"","page":"Home","title":"Home","text":"SecureArithmetic.jl is available under the MIT license (see License). Contributions by the community are very welcome! For larger proposed changes, feel free to reach out via an issue first.","category":"page"}]
}
