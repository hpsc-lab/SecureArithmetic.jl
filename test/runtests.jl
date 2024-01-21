using Test

@time @testset verbose=true showtiming=true "SecureArithmetic.jl tests" begin
    include("test_unit.jl")
    include("test_examples.jl")
end

