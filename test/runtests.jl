using Test

@time @testset verbose=true showtiming=true "SecureArithmetic.jl tests" begin
    include("test_examples.jl")
    include("test_unit.jl")
end

