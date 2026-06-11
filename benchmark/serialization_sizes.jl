using SecureArithmetic
using Serialization
using OpenFHE
using Printf

function format_bytes(n)
    if n >= 1_000_000
        return @sprintf("%.2f MB", n / 1_000_000)
    elseif n >= 1_000
        return @sprintf("%.2f KB", n / 1_000)
    else
        return @sprintf("%d B", n)
    end
end

function measure_sizes(context, public_key, private_key, secure_vector)
    objects = [
        ("SecureContext", context),
        ("PublicKey",     public_key),
        ("PrivateKey",    private_key),
        ("SecureVector",  secure_vector),
    ]

    results = Dict{String, Int}()

    for (name, obj) in objects
        io = IOBuffer()
        serialize(io, obj)
        results[name] = position(io)
    end

    return results
end

function print_results(results, label)
    objects = ["SecureContext", "PublicKey", "PrivateKey", "SecureVector"]

    println("### $label")
    println()
    println("| Object | Size |")
    println("| --- | --- |")
    for name in objects
        haskey(results, name) || continue
        println("| $name | $(format_bytes(results[name])) |")
    end
    println()
end

security_levels = [
    ("HEStd_128_classic", HEStd_128_classic),
    ("HEStd_192_classic", HEStd_192_classic),
    ("HEStd_256_classic", HEStd_256_classic),
]

multiplicative_depth = 2
scaling_modulus = 50
batch_size = 8
x1 = [0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0]

for (level_name, level) in security_levels
    parameters = CCParams{CryptoContextCKKSRNS}()
    SetMultiplicativeDepth(parameters, multiplicative_depth)
    SetScalingModSize(parameters, scaling_modulus)
    SetBatchSize(parameters, batch_size)
    SetSecurityLevel(parameters, level)

    cc = GenCryptoContext(parameters)
    Enable(cc, PKE)
    Enable(cc, KEYSWITCH)
    Enable(cc, LEVELEDSHE)

    ring_dim = GetRingDimension(cc)

    context = SecureContext(OpenFHEBackend(cc))
    public_key, private_key = generate_keys(context)
    init_multiplication!(context, private_key)

    pv = PlainVector(x1, context)
    sv = encrypt(pv, public_key)

    results = measure_sizes(context, public_key, private_key, sv)
    print_results(results, "$level_name (ring dimension = $ring_dim)")

    release_context_memory()
    GC.gc()
end
