# Remote Computation with ObliviousOffload.jl

Homomorphic encryption is perfectly suited to process sensitive data on a remote server without
exposing the underlying plaintext. A client encrypts its data locally, sends the ciphertext and public key
to the server, and the server performs computations entirely on encrypted data before
returning the encrypted result. The client can then decrypt the result with its private key.

[ObliviousOffload.jl](https://github.com/hpsc-lab/ObliviousOffload.jl) provides exactly
this client–server workflow on top of SecureArithmetic.jl. It handles TLS-secured HTTP
transport, serialization of SecureArithmetic objects, and a simple
`register_service!` / `offload` API.

The basic layout for offloading computations using SecureArithmetic entails a client and a server side:
* The server is a Julia program running in the background and waiting for connections. It accepts user data (the "payload"), processes with a predetermined algorithm (the "service"), and returns the result.
* The client is a Julia program that connects to that server, transfers the encrypted payload, selects a service with which the server should process it, and then retrieves the result. That is, the client "offloads" its data processing to the server.

Say you have the following stand-alone Secure Arithmetic code which (given a secure context) adds two vectors component wise.
```jldoctest OblOffl-example-all; filter = [r"(4\.99\d+|5\.0\d*)" => s"5.0", r"(6\.99\d+|7\.0\d*)" => s"7.0", r"(8\.99\d+|9\.0\d*)" => s"9.0"]
using SecureArithmetic
using OpenFHE

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 5)

rescale_technique = FLEXIBLEAUTO
dcrt_bits = 59
first_modulus = 60

SetScalingModSize(parameters, dcrt_bits)
SetScalingTechnique(parameters, rescale_technique)
SetFirstModSize(parameters, first_modulus)

level_budget = [4, 4]

levels_available_after_bootstrap = 10
depth = levels_available_after_bootstrap + GetBootstrapDepth(level_budget, secret_key_distribution)
SetMultiplicativeDepth(parameters, depth)

cc = GenCryptoContext(parameters)

Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
Enable(cc, ADVANCEDSHE)
Enable(cc, FHE)

ring_dimension = GetRingDimension(cc)
# This is the maximum number of slots that can be used for full packing.
num_slots = div(ring_dimension,  2)

EvalBootstrapSetup(cc; level_budget)

context = SecureContext(OpenFHEBackend(cc))

public_key, private_key = generate_keys(context)

x = [1,2,3]
y = [4,5,6]

s_x = encrypt(PlainArray(x, context), public_key)
s_y = encrypt(PlainArray(y, context), public_key)

function add(a, b)
    return a + b
end

s_result = add(s_x, s_y)
result = collect(decrypt(s_result, private_key))

result

# output

3-element Vector{Float64}:
 5.0
 7.0
 9.0
```

Now we want to split this into a server side and a client side part. We start with the client code, where we prepare the required data as before.

```jldoctest OblOffl-example; output = false
using SecureArithmetic
using OpenFHE
using ObliviousOffload

parameters = CCParams{CryptoContextCKKSRNS}()

secret_key_distribution = UNIFORM_TERNARY
SetSecretKeyDist(parameters, secret_key_distribution)

SetSecurityLevel(parameters, HEStd_NotSet)
SetRingDim(parameters, 1 << 5)

rescale_technique = FLEXIBLEAUTO
dcrt_bits = 59
first_modulus = 60

SetScalingModSize(parameters, dcrt_bits)
SetScalingTechnique(parameters, rescale_technique)
SetFirstModSize(parameters, first_modulus)

level_budget = [4, 4]

levels_available_after_bootstrap = 10
depth = levels_available_after_bootstrap + GetBootstrapDepth(level_budget, secret_key_distribution)
SetMultiplicativeDepth(parameters, depth)

cc = GenCryptoContext(parameters)

Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)
Enable(cc, ADVANCEDSHE)
Enable(cc, FHE)

ring_dimension = GetRingDimension(cc)
# This is the maximum number of slots that can be used for full packing.
num_slots = div(ring_dimension,  2)

EvalBootstrapSetup(cc; level_budget)

context = SecureContext(OpenFHEBackend(cc))

public_key, private_key = generate_keys(context)

x = [1,2,3]
y = [4,5,6]
 
s_x = encrypt(PlainArray(x, context), public_key)
s_y = encrypt(PlainArray(y, context), public_key)

# output

SecureVector{OpenFHEBackend{CxxWrap.StdLib.SharedPtrAllocated{OpenFHE.CryptoContextImpl{DCRTPoly}}}, Vector{CxxWrap.StdLib.SharedPtr{OpenFHE.CiphertextImpl{T}} where T}}(CxxWrap.StdLib.SharedPtr{OpenFHE.CiphertextImpl{T}} where T[Ciphertext{DCRTPoly}()], (3,), 16, )
```

For the server, we create a server object with ObliviousOffload.jl. We then define a function that the server should perform with the user data (here called `add`) and then register it as a service that the server provides to the user (again called `"add"`).

```jldoctest OblOffl-example
using SecureArithmetic
using ObliviousOffload
function add(a, b)
    return a + b
end

conn = ConnectParams()
server = OffloadServer(conn)

register_service!(server, "add", add)

# output

-----
-----
Certificate request self-signature ok
subject=CN=localhost
[ Info: ObliviousOffload server listening on 0.0.0.0:8080 (TLS), certificate for 'localhost'

```

Upon the first startup, the server will generally generate a certificate which it will use to communicate with the client securely.
This certificate has to be accepted once on the client side, to establish the server as a trusted peer.
To perform this procedure, run server.jl and client.jl from the [handshake example](https://github.com/hpsc-lab/ObliviousOffload.jl/tree/main/examples/handshake).


Once the handshake is complete and thus the trusted certificate in place, we can offload the computation to the server and receive the result back.
We thus execute the following code on the client side.
```jldoctest OblOffl-example; filter = [r".*POST /add.*", r"(4\.99\d+|5\.0\d*)" => s"5.0", r"(6\.99\d+|7\.0\d*)" => s"7.0", r"(8\.99\d+|9\.0\d*)" => s"9.0"]
conn = ConnectParams()

s_result = offload(conn, "add", s_x, s_y)
result = collect(decrypt(s_result, private_key))

result

# output

15/Sep/2026:10:05:28] "POST /add HTTP/1.1.0" 200 2.441s
3-element Vector{Float64}:
 5.0
 7.0
 9.0

```

For another practical example of how to use ObliviousOffload.jl, see the provided [simple array operations example](https://github.com/hpsc-lab/ObliviousOffload.jl/tree/main/examples/simple_array_operations) and the
[ObliviousOffload.jl documentation](https://hpsc-lab.github.io/ObliviousOffload.jl/stable).
