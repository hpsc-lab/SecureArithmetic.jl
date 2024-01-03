using Documenter

# Get SecureArithmetic.jl root directory
securearithmetic_root_dir = dirname(@__DIR__)

# Fix for https://github.com/trixi-framework/Trixi.jl/issues/668
if (get(ENV, "CI", nothing) != "true") && (get(ENV, "SECUREARITHMETIC_DOC_DEFAULT_ENVIRONMENT", nothing) != "true")
    push!(LOAD_PATH, securearithmetic_root_dir)
end

using SecureArithmetic 

# Define module-wide setups such that the respective modules are available in doctests
DocMeta.setdocmeta!(SecureArithmetic, :DocTestSetup, :(using SecureArithmetic); recursive=true)

# Copy some files from the top level directory to the docs and modify them
# as necessary
open(joinpath(@__DIR__, "src", "index.md"), "w") do io
    # Point to source file
    println(io, """
    ```@meta
    EditURL = "https://github.com/sloede/SecureArithmetic.jl/blob/main/README.md"
    ```
    """)
    # Write the modified contents
    for line in eachline(joinpath(securearithmetic_root_dir, "README.md"))
        line = replace(line, "[LICENSE.md](LICENSE.md)" => "[License](@ref)")
        println(io, line)
    end
end

open(joinpath(@__DIR__, "src", "license.md"), "w") do io
    # Point to source file
    println(io, """
    ```@meta
    EditURL = "https://github.com/sloede/SecureArithmetic/blob/main/LICENSE.md"
    ```
    """)
    # Write the modified contents
    println(io, "# License")
    println(io, "")
    for line in eachline(joinpath(securearithmetic_root_dir, "LICENSE.md"))
        println(io, "> ", line)
    end
end

# Make documentation
makedocs(
    # Specify modules for which docstrings should be shown
    modules = [SecureArithmetic],
    # Set sitename to Trixi.jl
    sitename="SecureArithmetic.jl",
    # Provide additional formatting options
    format = Documenter.HTML(
        # Disable pretty URLs during manual testing
        prettyurls = get(ENV, "CI", nothing) == "true",
        # Set canonical URL to GitHub pages URL
        canonical = "https://securearithmetic-jl.lakemper.eu/stable"
    ),
    # Explicitly specify documentation structure
    pages = [
        "Home" => "index.md",
        "API Reference" => "reference.md",
        "License" => "license.md"
    ],
)


deploydocs(;
    repo = "github.com/sloede/SecureArithmetic.jl",
    devbranch = "main",
    push_preview = true
)
