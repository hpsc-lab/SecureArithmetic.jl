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
        json = serialize(ct)
        @test json isa String
        @test !isempty(json)
        ct_deserialized = deserialize(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, json)
        @test ct_deserialized isa OpenFHE.Ciphertext{OpenFHE.DCRTPoly}
    end
end

@testset verbose=true showtiming=true "CryptoContext" begin
    json = serialize(cc)
    @test json isa String
    @test !isempty(json)
    cc_deserialized = deserialize(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, json)
    @test cc_deserialized isa OpenFHE.CryptoContext{OpenFHE.DCRTPoly}
end

@testset verbose=true showtiming=true "PublicKey" begin
    json = serialize(public_key.public_key)
    @test json isa String
    @test !isempty(json)
    pk_deserialized = deserialize(OpenFHE.PublicKey{OpenFHE.DCRTPoly}, json)
    @test pk_deserialized isa OpenFHE.PublicKey{OpenFHE.DCRTPoly}
end

@testset verbose=true showtiming=true "PrivateKey" begin
    json = serialize(private_key.private_key)
    @test json isa String
    @test !isempty(json)
    sk_deserialized = deserialize(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, json)
    @test sk_deserialized isa OpenFHE.PrivateKey{OpenFHE.DCRTPoly}
end

# Note: shape and capacity must be transmitted as metadata alongside the serialized
# ciphertexts, since OpenFHE serialization does not preserve this information.
@testset verbose=true showtiming=true "roundtrip vector" begin
    cc_restored = deserialize(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, serialize(cc))
    context_restored = SecureContext(OpenFHEBackend(cc_restored))

    sk_restored = SecureArithmetic.PrivateKey(context_restored,
        deserialize(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, serialize(private_key.private_key)))

    restored_cts = map(sv1.data) do ct
        deserialize(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, serialize(ct))
    end
    sv_restored = SecureArray(collect(restored_cts), size(sv1), capacity(sv1), context_restored)

    @test collect(decrypt(sv_restored, sk_restored)) ≈ collect(decrypt(sv1, private_key))
end

x2 = [0.25 0.5; 0.75 1.0; 2.0 3.0; 4.0 5.0]
pm1 = PlainMatrix(x2, context)
sm1 = encrypt(pm1, public_key)

@testset verbose=true showtiming=true "roundtrip matrix" begin
    cc_restored = deserialize(OpenFHE.CryptoContext{OpenFHE.DCRTPoly}, serialize(cc))
    context_restored = SecureContext(OpenFHEBackend(cc_restored))

    sk_restored = SecureArithmetic.PrivateKey(context_restored,
        deserialize(OpenFHE.PrivateKey{OpenFHE.DCRTPoly}, serialize(private_key.private_key)))

    restored_cts = map(sm1.data) do ct
        deserialize(OpenFHE.Ciphertext{OpenFHE.DCRTPoly}, serialize(ct))
    end
    sm_restored = SecureArray(collect(restored_cts), size(sm1), capacity(sm1), context_restored)

    @test collect(decrypt(sm_restored, sk_restored)) ≈ collect(decrypt(sm1, private_key))
end

release_context_memory()
GC.gc()

end # @testset "test_serialization.jl"

end # module
