using SecureArithmetic
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

function measure_sizes(cc, public_key, private_key, ciphertext)
    objects = [
        ("CryptoContext", cc),
        ("PublicKey",     public_key.public_key),
        ("PrivateKey",    private_key.private_key),
        ("Ciphertext",    ciphertext),
    ]

    results = Dict{String, Dict{String, Int}}()

    mktempdir() do dir
        for (name, obj) in objects
            sizes = Dict{String, Int}()

            json_str = serialize_to_json_string(obj)
            sizes["string (JSON)"] = sizeof(json_str)

            bin_file = joinpath(dir, "$(name).bin")
            serialize_to_binary_file(bin_file, obj)
            sizes["binary file"] = filesize(bin_file)

            json_file = joinpath(dir, "$(name).json")
            serialize_to_json_file(json_file, obj)
            sizes["JSON file"] = filesize(json_file)

            results[name] = sizes
        end
    end

    return results
end

function print_results(results, label)
    objects = ["CryptoContext", "PublicKey", "PrivateKey", "Ciphertext"]
    formats = ["String (JSON)", "JSON file", "Binary file"]

    println("### $label")
    println()
    println("| Object | $(join(formats, " | ")) |")
    println("| $(join(fill("---", length(formats) + 1), " | ")) |")
    for name in objects
        haskey(results, name) || continue
        sizes = results[name]
        cols = [format_bytes(sizes[fmt]) for fmt in ["string (JSON)", "JSON file", "binary file"]]
        println("| $name | $(join(cols, " | ")) |")
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
    ct = sv.data[1]

    results = measure_sizes(cc, public_key, private_key, ct)
    print_results(results, "$level_name (ring dimension = $ring_dim)")

    release_context_memory()
    GC.gc()
end
