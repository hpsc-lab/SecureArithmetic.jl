module TestExamples

using Test
using SecureArithmetic

@testset verbose=true showtiming=true "test_examples.jl" begin

@testset verbose=true showtiming=true "examples/simple_real_numbers.jl" begin
    @test_nowarn include("../examples/simple_real_numbers.jl")
end

@testset verbose=true showtiming=true "examples/simple_ckks_bootstrapping.jl" begin
    @test_nowarn include("../examples/simple_ckks_bootstrapping.jl")
end

@testset verbose=true showtiming=true "examples/simple_matrix_operations.jl" begin
    @test_nowarn include("../examples/simple_matrix_operations.jl")
end

@testset verbose=true showtiming=true "examples/simple_array_operations.jl" begin
    @test_nowarn include("../examples/simple_array_operations.jl")
end

end # @testset "test_examples.jl"

end # module

