module TestExamples

using Test
using SecureArithmetic

@testset verbose=true showtiming=true "test_examples.jl" begin

@testset verbose=true showtiming=true "examples/simple_real_numbers.jl" begin
    @test_nowarn include("../examples/simple_real_numbers.jl")
end

end # @testset "test_examples.jl"

end # module

