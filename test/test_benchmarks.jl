module TestBenchmarks

using Test
using SecureArithmetic

@testset verbose=true showtiming=true "test_benchmarks.jl" begin

@testset verbose=true showtiming=true "benchmark/serialization_sizes.jl" begin
    @testset "smoketest" begin
        @test_nowarn include("../benchmark/serialization_sizes.jl")
    end
    @testset "format_bytes" begin
        @test format_bytes(0) == "0 B"
        @test format_bytes(1) == "1 B"
        @test format_bytes(999) == "999 B"
        @test format_bytes(1_000) == "1.00 KB"
        @test format_bytes(1_500) == "1.50 KB"
        @test format_bytes(999_999) == "1000.00 KB"
        @test format_bytes(1_000_000) == "1.00 MB"
        @test format_bytes(2_500_000) == "2.50 MB"
        @test format_bytes(2_500_000_000) == "2500.00 MB"
    end
end

end # @testset "test_benchmarks.jl"

end # module
