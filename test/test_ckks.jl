module TestCKKS

using Test
using SecureArithmetic

@testset verbose=true showtiming=true "dummy" begin
    @test_nowarn SecureArithmetic.greet()
end

end # module
