using SecureArithmetic
using OpenFHE

function simple_real_numbers(context)
    public_key, private_key = generate_keys(context)

    init_multiplication(context, private_key)
    init_rotation(context, private_key, [1, -2])


    x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]
    x2 = [5.0, 4.0, 3.0, 2.0, 1.0, 0.75, 0.5, 0.25]

    pv1 = PlainVector(context, x1)
    pv2 = PlainVector(context, x2)

    println("Input x1: ", pv1)
    println("Input x2: ", pv2)

    sv1 = encrypt(context, public_key, pv1)
    sv2 = encrypt(context, public_key, pv2)

    sv_add = sv1 + sv2

    sv_sub = sv1 - sv2

    sv_scalar = sv1 * 4.0

    sv_mult = sv1 * sv2

    sv_shift1 = circshift(sv1, -1)
    sv_shift2 = circshift(sv1, 2)


    println()
    println("Results of homomorphic computations: ")

    result_sv1 = decrypt(context, private_key, sv1)
    println("x1 = ", result_sv1)

    result_sv_add = decrypt(context, private_key, sv_add)
    println("x1 + x2 = ", result_sv_add)

    result_sv_sub = decrypt(context, private_key, sv_sub)
    println("x1 - x2 = ", result_sv_sub)

    result_sv_scalar = decrypt(context, private_key, sv_scalar)
    println("4 * x1 = ", result_sv_scalar)

    result_sv_mult = decrypt(context, private_key, sv_mult)
    println("x1 * x2 = ", result_sv_mult)

    result_sv_shift1 = decrypt(context, private_key, sv_shift1)
    println("x1 shifted circularly by -1 = ", result_sv_shift1)

    result_sv_shift2 = decrypt(context, private_key, sv_shift2)
    println("x1 shifted circularly by 2 = ", result_sv_shift2)
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

context_unencrypted = SecureContext(Unencrypted())


################################################################################
println("="^80)
println("simple_real_numbers with an OpenFHE context")
simple_real_numbers(context_openfhe)


################################################################################
println("="^80)
println("simple_real_numbers with an Unencrypted context")
simple_real_numbers(context_unencrypted)

