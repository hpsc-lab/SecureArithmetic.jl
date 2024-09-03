module TestUnit

using Test
using SecureArithmetic
using OpenFHE

@testset verbose=true showtiming=true "test_unit.jl" begin

# Set up OpenFHE backend
multiplicative_depth = 1
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
context_openfhe = SecureContext(OpenFHEBackend(cc))

# Set up unencrypted backend
context_unencrypted = SecureContext(Unencrypted())

for backend in ((; name = "OpenFHE", BackendT = OpenFHEBackend, context = context_openfhe),
                (; name = "Unencrypted", BackendT = Unencrypted, context = context_unencrypted))
    (; name, BackendT, context) = backend

    @testset verbose=true showtiming=true "$name" begin
        @testset verbose=true showtiming=true "generate_keys" begin
            @test_nowarn generate_keys(context)
        end
        public_key, private_key = generate_keys(context)

        @testset verbose=true showtiming=true "init_multiplication!" begin
            @test_nowarn init_multiplication!(context, private_key)
        end

        @testset verbose=true showtiming=true "init_rotation!" begin
            @test_nowarn init_rotation!(context, private_key, [1, -2])
        end

        @testset verbose=true showtiming=true "init_matrix_rotation!" begin
            @test_nowarn init_matrix_rotation!(context, private_key, [(1, -1), (-1, 0), (1, 1),
                                                                      (0, 1), (1, 0)], (4, 2))
            @test_nowarn init_matrix_rotation!(context, private_key, (2, 0), (4, 2))
        end

        x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
        x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]
        m1 = [0.25 0.5;
              0.75 1.0;
              2.0 3.0;
              4.0 5.0]
        m2 = [5.0 4.0;
              3.0 2.0;
              1.0 0.75;
              0.5 0.25]

        @testset verbose=true showtiming=true "PlainVector" begin
            @test PlainVector(x1, context) isa PlainVector
            @test PlainVector([1, 2, 3], context) isa PlainVector
        end

        pv1 = PlainVector(x1, context)
        pv2 = PlainVector(x2, context)

        @testset verbose=true showtiming=true "PlainMatrix" begin
            @test PlainMatrix(m1, context) isa PlainMatrix
            @test PlainMatrix([1, 2, 3, 4], context, (2, 2)) isa PlainMatrix
        end

        pm1 = PlainMatrix(m1, context)
        pm2 = PlainMatrix(m2, context)

        @testset verbose=true showtiming=true "encrypt" begin
            @test encrypt(pv1, public_key) isa SecureVector
            @test encrypt([1.0, 2.0, 3.0], public_key, context) isa SecureVector
            @test encrypt(pm1, public_key) isa SecureMatrix
            @test encrypt([1.0 2.0; 3.0 4.0], public_key, context) isa SecureMatrix
        end

        sv1 = encrypt(pv1, public_key)
        sv2 = encrypt(pv2, public_key)
        sm1 = encrypt(pm1, public_key)
        sm2 = encrypt(pm2, public_key)

        @testset verbose=true showtiming=true "add" begin
            @test sv1 + sv2 isa SecureVector
            @test sv1 + pv1 isa SecureVector
            @test pv1 + sv1 isa SecureVector
            @test sv1 + 3 isa SecureVector
            @test 4 + sv1 isa SecureVector
            @test sm1 + sm2 isa SecureMatrix
            @test sm1 + pm1 isa SecureMatrix
            @test pm1 + sm1 isa SecureMatrix
            @test sm1 + 3 isa SecureMatrix
            @test 4 + sm1 isa SecureMatrix
        end

        @testset verbose=true showtiming=true "subtract" begin
            @test sv1 - sv2 isa SecureVector
            @test sv1 - pv1 isa SecureVector
            @test pv1 - sv1 isa SecureVector
            @test sv1 - 3 isa SecureVector
            @test 4 - sv1 isa SecureVector
            @test sm1 - sm2 isa SecureMatrix
            @test sm1 - pm1 isa SecureMatrix
            @test pm1 - sm1 isa SecureMatrix
            @test sm1 - 3 isa SecureMatrix
            @test 4 - sm1 isa SecureMatrix
        end

        @testset verbose=true showtiming=true "multiply" begin
            @test sv1 * sv2 isa SecureVector
            @test sv1 * pv1 isa SecureVector
            @test pv1 * sv1 isa SecureVector
            @test sv1 * 3 isa SecureVector
            @test 4 * sv1 isa SecureVector
            @test sm1 * sm2 isa SecureMatrix
            @test sm1 * pm1 isa SecureMatrix
            @test pm1 * sm1 isa SecureMatrix
            @test sm1 * 3 isa SecureMatrix
            @test 4 * sm1 isa SecureMatrix
        end

        @testset verbose=true showtiming=true "negate" begin
            @test -sv2 isa SecureVector
            @test -sm2 isa SecureMatrix
        end

        sv_short = encrypt([1.0, 2.0, 3.0], public_key, context)

        @testset verbose=true showtiming=true "circshift" begin
            @test circshift(sv_short, 1) isa SecureVector
            @test circshift(sv_short, 0) isa SecureVector
            @test_throws ArgumentError circshift(sv_short, 1; wrap_by = :wololo)
            @test circshift(sv_short, 1; wrap_by = :length) isa SecureVector
            @test circshift(sv_short, -2; wrap_by = :length) isa SecureVector
            @test collect(decrypt(circshift(sv_short, 1; wrap_by = :length), private_key)) ≈
                [3.0, 1.0, 2.0]
            @test collect(decrypt(circshift(sv_short, -2; wrap_by = :length), private_key)) ≈
                [3.0, 1.0, 2.0]
            @test collect(decrypt(circshift(sv1, 1), private_key)) ≈
                [5.0, 0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0]
            @test collect(decrypt(circshift(sv1, -2), private_key)) ≈
                [0.75, 1.0, 2.0, 3.0, 4.0, 5.0, 0.25, 0.5]
            @test collect(decrypt(circshift(sm1, (1, -1)), private_key)) ≈ circshift(m1, (1, -1))
            @test collect(decrypt(circshift(sm1, (1, 1)), private_key)) ≈ circshift(m1, (1, 1))
            @test collect(decrypt(circshift(sm1, (-1, 0)), private_key)) ≈ circshift(m1, (-1, 0))
            @test collect(decrypt(circshift(sm1, (0, 1)), private_key)) ≈ circshift(m1, (0, 1))
            @test collect(decrypt(circshift(sm1, (1, 0)), private_key)) ≈ circshift(m1, (1, 0))
            @test collect(decrypt(circshift(sm1, (0, 0)), private_key)) ≈ m1
        end

        @testset verbose=true showtiming=true "length" begin
            @test length(pv1) == length(x1)
            @test length(sv1) == length(pv1)
        end

        @testset verbose=true showtiming=true "size" begin
            @test size(pm1) == size(m1)
            @test size(sm1) == size(pm1)
        end

        @testset verbose=true showtiming=true "capacity" begin
            @test capacity(pv1) == 8
            @test capacity(sv1) == 8
            @test capacity(pm1) == 8
            @test capacity(sm1) == 8
        end

        @testset verbose=true showtiming=true "level" begin
            @test level(pv1) == 0
            @test level(sv1) == 0
            @test level(pm1) == 0
            @test level(sm1) == 0
        end

        @testset verbose=true showtiming=true "collect" begin
            @test collect(pv1) ≈ x1
            @test collect(pm1) ≈ m1
        end

        @testset verbose=true showtiming=true "show" begin
            @test_nowarn show(stdout, context)
            println()

            @test_nowarn show(stdout, pv1)
            println()

            @test_nowarn show(stdout, MIME"text/plain"(), pv1)
            println()

            @test_nowarn show(stdout, sv1)
            println()

            @test_nowarn show(stdout, pm1)
            println()

            @test_nowarn show(stdout, MIME"text/plain"(), pm1)
            println()

            @test_nowarn show(stdout, sm1)
            println()

            @test_nowarn show(stdout, public_key)
            println()

            @test_nowarn show(stdout, private_key)
            println()
        end

        release_context_memory()
        GC.gc()
    end
end

end # @testset "test_unit.jl"

end # module

