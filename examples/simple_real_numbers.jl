using SecureArithmetic
using OpenFHE

function simple_real_numbers(context)
    public_key, private_key = generate_keys(context)

    init_multiplication!(context, private_key)
    init_rotation!(context, private_key, [-1, 2])


    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

    pv1 = PlainVector(x1, context)
    pv2 = PlainVector(x2, context)

    println("Input x1: ", pv1)
    println("Input x2: ", pv2)

    sv1 = encrypt(pv1, public_key)
    sv2 = encrypt(pv2, public_key)

    sv_add = sv1 + sv2

    sv_sub = sv1 - sv2

    sv_scalar = sv1 * 4.0

    sv_mult = sv1 * sv2

    sv_shift1 = circshift(sv1, -1)
    sv_shift2 = circshift(sv1, 2)


    println()
    println("Results of homomorphic computations: ")

    result_sv1 = decrypt(sv1, private_key)
    println("x1 = ", result_sv1)

    result_sv_add = decrypt(sv_add, private_key)
    println("x1 + x2 = ", result_sv_add)

    result_sv_sub = decrypt(sv_sub, private_key)
    println("x1 - x2 = ", result_sv_sub)

    result_sv_scalar = decrypt(sv_scalar, private_key)
    println("4 * x1 = ", result_sv_scalar)

    result_sv_mult = decrypt(sv_mult, private_key)
    println("x1 * x2 = ", result_sv_mult)

    result_sv_shift1 = decrypt(sv_shift1, private_key)
    println("x1 shifted circularly by -1 = ", result_sv_shift1)

    result_sv_shift2 = decrypt(sv_shift2, private_key)
    println("x1 shifted circularly by 2 = ", result_sv_shift2)
    
    # Clean all `OpenFHE.CryptoContext`s and generated keys.
    release_context_memory()
end


################################################################################
println("="^80)
println("Creating OpenFHE context...")

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
println("CKKS scheme is using ring dimension ", GetRingDimension(cc))
println()

context_openfhe = SecureContext(OpenFHEBackend(cc))


################################################################################
println("="^80)
println("Creating unencrypted context...")
println()

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_real_numbers with an OpenFHE context")
simple_real_numbers(context_openfhe)
println()


################################################################################
println("="^80)
println("simple_real_numbers with an Unencrypted context")
simple_real_numbers(context_unencrypted)

