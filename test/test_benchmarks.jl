module TestBenchmarks

using Test
using SecureArithmetic

@testset verbose=true showtiming=true "test_benchmarks.jl" begin

@testset verbose=true showtiming=true "benchmark/serialization_sizes.jl" begin
    @test_nowarn include("../benchmark/serialization_sizes.jl")
end

end # @testset "test_benchmarks.jl"

end # module
