module TestSerialization

using Test
using SecureArithmetic
using OpenFHE

@testset verbose=true showtiming=true "test_serialization.jl" begin

multiplicative_depth = 2
scaling_modulus = 50
batch_size = 8

parameters = CCParams{CryptoContextCKKSRNS}()
SetMultiplicativeDepth(parameters, multiplicative_depth)
SetScalingModSize(parameters, scaling_modulus)
SetBatchSize(parameters, batch_size)

cc = GenCryptoContext(parameters)
Enable(cc, PKE)
Enable(cc, KEYSWITCH)
Enable(cc, LEVELEDSHE)

context = SecureContext(OpenFHEBackend(cc))
public_key, private_key = generate_keys(context)

x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
pv1 = PlainVector(x1, context)
sv1 = encrypt(pv1, public_key)

@testset verbose=true showtiming=true "Ciphertext" begin
    for ct in sv1.data
        json = serialize_to_json_string(ct)
        @test json isa String
        @test !isempty(json)
        ct_deserialized = deserialize_from_json_string(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, json)
        @test ct_deserialized isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}
    end
end

@testset verbose=true showtiming=true "CryptoContext" begin
    json = serialize_to_json_string(cc)
    @test json isa String
    @test !isempty(json)
    cc_deserialized = deserialize_from_json_string(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, json)
    @test cc_deserialized isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}
end

@testset verbose=true showtiming=true "PublicKey" begin
    json = serialize_to_json_string(public_key.public_key)
    @test json isa String
    @test !isempty(json)
    pk_deserialized = deserialize_from_json_string(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, json)
    @test pk_deserialized isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}
end

@testset verbose=true showtiming=true "PrivateKey" begin
    json = serialize_to_json_string(private_key.private_key)
    @test json isa String
    @test !isempty(json)
    sk_deserialized = deserialize_from_json_string(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, json)
    @test sk_deserialized isa OpenFHE.PrivateKey{OpenFHE.DCRTPoly}
end

# Note: shape and capacity must be transmitted as metadata alongside the serialized
# ciphertexts, since OpenFHE serialization does not preserve this information.
@testset verbose=true showtiming=true "roundtrip vector" begin
    cc_restored = deserialize_from_json_string(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, serialize_to_json_string(cc))
    context_restored = SecureContext(OpenFHEBackend(cc_restored))

    sk_restored = SecureArithmetic.PrivateKey(context_restored,
        deserialize_from_json_string(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, serialize_to_json_string(private_key.private_key)))

    restored_cts = map(sv1.data) do ct
        deserialize_from_json_string(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, serialize_to_json_string(ct))
    end
    sv_restored = SecureArray(collect(restored_cts), size(sv1), capacity(sv1), context_restored)

    @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
end

x2 = [0.25 0.5; 0.75 1.0; 2.0 3.0; 4.0 5.0]
pm1 = PlainMatrix(x2, context)
sm1 = encrypt(pm1, public_key)

@testset verbose=true showtiming=true "roundtrip matrix" begin
    cc_restored = deserialize_from_json_string(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, serialize_to_json_string(cc))
    context_restored = SecureContext(OpenFHEBackend(cc_restored))

    sk_restored = SecureArithmetic.PrivateKey(context_restored,
        deserialize_from_json_string(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, serialize_to_json_string(private_key.private_key)))

    restored_cts = map(sm1.data) do ct
        deserialize_from_json_string(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, serialize_to_json_string(ct))
    end
    sm_restored = SecureArray(collect(restored_cts), size(sm1), capacity(sm1), context_restored)

    @test collect(decrypt(sm_restored, sk_restored)) ≈ collect(decrypt(sm1, private_key))
end

@testset verbose=true showtiming=true "serialize_to_binary_file / deserialize_from_binary_file" begin
    mktempdir() do dir
        cc_file = joinpath(dir, "cc.bin")
        pk_file = joinpath(dir, "pk.bin")
        sk_file = joinpath(dir, "sk.bin")
        ct_file = joinpath(dir, "ct.bin")

        @test serialize_to_binary_file(cc_file, cc) == true
        @test serialize_to_binary_file(pk_file, public_key.public_key) == true
        @test serialize_to_binary_file(sk_file, private_key.private_key) == true
        @test serialize_to_binary_file(ct_file, sv1.data[1]) == true

        cc_restored = deserialize_from_binary_file(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, cc_file)
        @test cc_restored isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}

        context_restored = SecureContext(OpenFHEBackend(cc_restored))

        pk_restored = deserialize_from_binary_file(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, pk_file)
        @test pk_restored isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}

        sk_restored = SecureArithmetic.PrivateKey(context_restored,
            deserialize_from_binary_file(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, sk_file))

        ct_restored = deserialize_from_binary_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, ct_file)
        @test ct_restored isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}

        restored_cts = map(sv1.data) do ct
            f = joinpath(dir, "ct_tmp.bin")
            serialize_to_binary_file(f, ct)
            deserialize_from_binary_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, f)
        end
        sv_restored = SecureArray(collect(restored_cts), size(sv1), capacity(sv1), context_restored)
        @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
    end
end

@testset verbose=true showtiming=true "serialize_to_json_file / deserialize_from_json_file" begin
    mktempdir() do dir
        cc_file = joinpath(dir, "cc.json")
        pk_file = joinpath(dir, "pk.json")
        sk_file = joinpath(dir, "sk.json")
        ct_file = joinpath(dir, "ct.json")

        @test serialize_to_json_file(cc_file, cc) == true
        @test serialize_to_json_file(pk_file, public_key.public_key) == true
        @test serialize_to_json_file(sk_file, private_key.private_key) == true
        @test serialize_to_json_file(ct_file, sv1.data[1]) == true

        cc_restored = deserialize_from_json_file(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, cc_file)
        @test cc_restored isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}

        context_restored = SecureContext(OpenFHEBackend(cc_restored))

        pk_restored = deserialize_from_json_file(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, pk_file)
        @test pk_restored isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}

        sk_restored = SecureArithmetic.PrivateKey(context_restored,
            deserialize_from_json_file(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, sk_file))

        ct_restored = deserialize_from_json_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, ct_file)
        @test ct_restored isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}

        restored_cts = map(sv1.data) do ct
            f = joinpath(dir, "ct_tmp.json")
            serialize_to_json_file(f, ct)
            deserialize_from_json_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, f)
        end
        sv_restored = SecureArray(collect(restored_cts), size(sv1), capacity(sv1), context_restored)
        @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
    end
end

@testset verbose=true showtiming=true "type stability" begin
    ct = sv1.data[1]
    json = serialize_to_json_string(ct)
    # @inferred throws an Error if the return type is not what the compiler inferred. See https://docs.julialang.org/en/v1/stdlib/Test/#Test.@inferred
    # @test catches the Error if one is thrown. 
    # If no error is thrown, @inferred returns what the function return and @test compares the returned value to the type we expected
    @test @inferred(serialize_to_json_string(ct)) isa String
    @test @inferred(serialize_to_json_string(cc)) isa String
    @test @inferred(serialize_to_json_string(public_key.public_key)) isa String
    @test @inferred(serialize_to_json_string(private_key.private_key)) isa String

    @test @inferred(deserialize_from_json_string(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, json)) isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}
    @test @inferred(deserialize_from_json_string(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, serialize_to_json_string(cc))) isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}
    @test @inferred(deserialize_from_json_string(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, serialize_to_json_string(public_key.public_key))) isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}
    @test @inferred(deserialize_from_json_string(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, serialize_to_json_string(private_key.private_key))) isa OpenFHE.PrivateKey{OpenFHE.DCRTPoly}

    mktempdir() do dir
        cc_file = joinpath(dir, "cc.bin")
        pk_file = joinpath(dir, "pk.bin")
        sk_file = joinpath(dir, "sk.bin")
        ct_file = joinpath(dir, "ct.bin")



        @test @inferred(serialize_to_binary_file(ct_file, ct)) isa Bool
        @test @inferred(serialize_to_binary_file(cc_file, cc)) isa Bool
        @test @inferred(serialize_to_binary_file(pk_file, public_key.public_key)) isa Bool
        @test @inferred(serialize_to_binary_file(sk_file, private_key.private_key)) isa Bool

        @test @inferred(deserialize_from_binary_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, ct_file)) isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_binary_file(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, cc_file)) isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_binary_file(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, pk_file)) isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_binary_file(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, sk_file)) isa OpenFHE.PrivateKey{OpenFHE.DCRTPoly}


        
        cc_file = joinpath(dir, "cc.json")
        pk_file = joinpath(dir, "pk.json")
        sk_file = joinpath(dir, "sk.json")
        ct_file = joinpath(dir, "ct.json")

        @test @inferred(serialize_to_json_file(ct_file, ct)) isa Bool
        @test @inferred(serialize_to_json_file(cc_file, cc)) isa Bool
        @test @inferred(serialize_to_json_file(pk_file, public_key.public_key)) isa Bool
        @test @inferred(serialize_to_json_file(sk_file, private_key.private_key)) isa Bool

        @test @inferred(deserialize_from_json_file(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, ct_file)) isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_json_file(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, cc_file)) isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_json_file(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, pk_file)) isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}
        @test @inferred(deserialize_from_json_file(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, sk_file)) isa OpenFHE.PrivateKey{OpenFHE.DCRTPoly}
    end
end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
