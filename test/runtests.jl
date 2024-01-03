using Test

@time @testset verbose=true showtiming=true "SecureArithmetic.jl tests" begin
    include("test_ckks.jl")
end

