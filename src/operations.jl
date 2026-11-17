"""
    encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)

Encrypt `data` into a [`SecureArray`](@ref) using the `public_key` derived for the given
`context`.

See also: [`SecureArray`](@ref), [`PublicKey`](@ref), [`SecureContext`](@ref), [`decrypt`](@ref)
"""
function encrypt(data::Array{<:Real}, public_key::PublicKey, context::SecureContext)
    encrypt_impl(data, public_key, context)
end

"""
    encrypt(plain_array::PlainArray, public_key::PublicKey)

Encrypt `plain_array` into a [`SecureArray`](@ref) using the `public_key`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PublicKey`](@ref), [`decrypt`](@ref)
"""
function encrypt(plain_array::PlainArray, public_key::PublicKey)
    encrypt_impl(plain_array, public_key)
end

"""
    decrypt!(plain_array::PlainArray, secure_array::SecureArray, private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and store the result in the given
`plain_array`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PrivateKey`](@ref), [`decrypt`](@ref)
"""
function decrypt!(plain_array::PlainArray, secure_array::SecureArray,
                  private_key::PrivateKey)
    decrypt_impl!(plain_array, secure_array, private_key)
end

"""
    decrypt(secure_array::SecureArray, private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and return the resulting `PlainArray`.

See also: [`PlainArray`](@ref), [`SecureArray`](@ref), [`PrivateKey`](@ref), [`decrypt!`](@ref)
"""
function decrypt(secure_array::SecureArray, private_key::PrivateKey)
    decrypt_impl(secure_array, private_key)
end


"""
    release_context_memory()

Release all `OpenFHE.CryptoContext`s and keys for multiplication, rotation, bootstrapping and
`OpenFHE.EvalSum` generated in the functions [`init_multiplication!`](@ref),
[`init_rotation!`](@ref), [`init_bootstrapping!`](@ref) and `OpenFHE.EvalSumKeyGen`.

In the source code of OpenFHE C++, all `CryptoContext`s and keys are stored in static objects.
Without using `release_context_memory`, the memory allocated for these contexts and keys will
only be freed after restarting the Julia REPL. It is also advisable to call `GC.gc()` after
a call to `release_context_memory` to clean up all memory on the Julia side.

See also: [`init_multiplication!`](@ref), [`init_rotation!`](@ref), [`init_bootstrapping!`](@ref)
"""
function release_context_memory()
    OpenFHE.ClearEvalMultKeys()
    OpenFHE.ClearEvalSumKeys()
    OpenFHE.ClearEvalAutomorphismKeys()
    OpenFHE.ReleaseAllContexts()
    
    nothing
end


############################################################################################
# Packed arrays
############################################################################################

# Tiling is only correct when the block length and the slot count divide one another. Both are powers of
# two for a packed array (due to padding), so neither error below should be reachable for FHE
# backends; the unencrypted backend has a single slot, which divides everything.
function check_packed_tiling(block::Integer, slots::Integer)
    if block < slots
        # A block shorter than a ciphertext is tiled `slots ÷ block` times to fill it. If it does
        # not divide the slot count, the last tile is cut off mid-block and a cyclic rotation of
        # the ciphertext stops being a block-cyclic rotation of the array: the wrap-around of such
        # a shift is supplied by the neighbouring tile, which is then no longer a full block.
        if slots % block != 0
            throw(ArgumentError("padded block length $block does not divide the $slots slots " *
                                "per ciphertext, so the block cannot be tiled to fill it exactly"))
        else
            # The ciphertext holds a whole number of blocks, so every tile is complete.
            nothing
        end
    elseif block > slots
        # A block longer than a ciphertext is not tiled at all but spread over `block ÷ slots`
        # ciphertexts. If the slot count does not divide the block, the last ciphertext has empty slots.
        if block % slots != 0
            throw(ArgumentError("the $slots slots per ciphertext do not divide the padded " *
                                "block length $block, so the block cannot be spread over whole " *
                                "ciphertexts"))
        else
            # The block is a whole number of ciphertexts, so none of them straddles its end.
            nothing
        end
    else # block == slots
        # One block fills exactly one ciphertext: a single tile, neither repeated nor split.
        nothing
    end

    nothing
end

"""
    PlainArrayPacked(data::Array{<:Real}, context::SecureContext)

Encode `data` into a [`PlainArrayPacked`](@ref), i.e. zero-pad every dimension to the next
power of two and tile the resulting block so that it fills the underlying storage exactly.

Matrix multiplication runs on this layout, so encoding a matrix this way instead of as a
[`PlainArray`](@ref) saves matrix multiplication the conversion; see [`PlainArrayPacked`](@ref) for why the
layout is cheaper and [`init_matrix_multiplication!`](@ref) for the corresponding rotation key logic.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref), [`encrypt`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
function PlainArrayPacked(data::Array{<:Real}, context::SecureContext)
    shape = size(data)
    padded_shape = ntuple(i -> next_power_of_two(shape[i]), ndims(data))
    block = prod(padded_shape)
    slots = slot_count(context)
    check_packed_tiling(block, slots)

    # Pad the *array*, not the flattened data. The original data occupies the top-left sub-block rather than a prefix.
    # I.e. both columns and rows can be padded
    padded = zeros(Float64, padded_shape)
    padded[map(Base.OneTo, shape)...] = data

    tiles = max(1, slots ÷ block)
    PlainArrayPacked(PlainArray(repeat(vec(padded), tiles), context),
                     shape, padded_shape)
end

"""
    PlainMatrixPacked(data::Matrix{<:Real}, context::SecureContext)

Encode `data` into a packed matrix. See [`PlainArrayPacked`](@ref).
"""
PlainMatrixPacked(data::Matrix{<:Real}, context::SecureContext) =
    PlainArrayPacked(data, context)

"""
    PlainVectorPacked(data::Vector{<:Real}, context::SecureContext)

Encode `data` into a packed vector. See [`PlainArrayPacked`](@ref).
"""
PlainVectorPacked(data::Vector{<:Real}, context::SecureContext) =
    PlainArrayPacked(data, context)

############################################################################################
# Repacking an array that is already encoded or encrypted
############################################################################################

# The packed layout of `shape`: every dimension rounded up to the next power of two,
# the length of one such block, and the storage a packed array of that block fills.
function packed_layout(shape::NTuple{N, Int}, slots::Integer) where N
    padded_shape = ntuple(i -> next_power_of_two(shape[i]), N)
    block = prod(padded_shape)
    check_packed_tiling(block, slots)

    (padded_shape, block, max(slots, block))
end

# How an unpacked array of `shape` maps onto the packed block of `padded_shape`.
#
# Both layouts are column-major and differ only in their strides, so the data decomposes into
# `prod(shape[2:end])` runs of `shape[1]` contiguous slots. The run indexed
# by the trailing indices `c` starts at `sum((c[k]-1) * prod(shape[1:k]))` and has to
# end up at the same sum taken over the *padded* strides, i.e. it moves as a block by the
# difference of the two offsets. Padding the first dimension is what drives the runs apart;
# padding any other dimension only appends whole zero blocks and moves nothing.
#
# Runs that move by the same amount share one mask and one rotation, so the result groups them
# as `shift => source offsets`, sorted by shift to keep the operation order reproducible.
function packing_runs(shape::NTuple{N, Int}, padded_shape::NTuple{N, Int}) where N
    original_strides = cumprod(collect(shape))
    padded_strides = cumprod(collect(padded_shape))

    runs = Dict{Int, Vector{Int}}()
    for c in CartesianIndices(shape[2:end])
        source = 0
        target = 0
        for k in 1:(N - 1)
            source += (c[k] - 1) * original_strides[k]
            target += (c[k] - 1) * padded_strides[k]
        end
        push!(get!(Vector{Int}, runs, target - source), source)
    end

    sort!(collect(runs), by = first)
end

# The `circshift` amounts that `SecureArrayPacked(::SecureArray)` applies to the flattened
# length-`storage` array: the non-zero run shifts, then the doublings that tile the block over
# the storage. Must be kept in sync with that constructor.
function compute_packing_shifts(shape::NTuple{N, Int},
                                padded_shape::NTuple{N, Int}, storage::Integer) where N
    shifts = Int[]
    for (shift, _) in packing_runs(shape, padded_shape)
        if shift != 0
            push!(shifts, shift)
        end
    end

    tile_shift = prod(padded_shape)
    while tile_shift < storage
        push!(shifts, tile_shift)
        tile_shift *= 2
    end

    unique(shifts)
end

"""
    SecureArrayPacked(secure_array::SecureArray)

Convert an already encrypted, unpacked [`SecureArray`](@ref) into a [`SecureArrayPacked`](@ref),
i.e. zero-pad every dimension to the next power of two and tile the resulting block so that it
fills the underlying storage exactly.

This is the ciphertext-side counterpart of `PlainArrayPacked(data, context)`, which does the
same thing in the clear and is therefore free. Here the layout has to be rebuilt
homomorphically: each run of contiguous slots is isolated with a plaintext mask, rotated to
its padded offset, and the pieces are added up. That costs one multiplicative level, or two
when the padded block spans several ciphertexts and the first dimension needs padding,
because then the rotations are masked as well - still less than running the multiplication
algorithm on an unpacked layout would cost. When every dimension is a power of two already
and the block fills at least one whole ciphertext, the conversion is a pure relabelling and
costs nothing at all.

`*` applies this conversion itself to a pair of flat operands, and unpacks the result again with
`SecureArray(::SecureArrayPacked)` so that a product keeps the layout of its operands. Calling it
explicitly is therefore only needed to convert an operand once for several products, to keep the
result packed, or to place the conversion at a specific point of the level budget. Requires the
rotation keys from [`init_packing!`](@ref), which [`init_matrix_multiplication!`](@ref) generates
as well unless `packed = true`.

See also: [`SecureArrayPacked`](@ref), [`PlainArrayPacked`](@ref), [`init_packing!`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
function SecureArrayPacked(secure_array::SecureArray)
    context = secure_array.context
    shape = size(secure_array)
    padded_shape, block, storage = packed_layout(shape, slot_count(context))

    # Nothing to move and nothing to zero, so this is a pure relabelling.
    if shape == padded_shape && length(secure_array) == storage &&
       capacity(secure_array) == storage
        return SecureArrayPacked(reshape(secure_array, (storage,)), shape, padded_shape)
    end

    # `resize` does not zero the slots it adds, it clones the first ciphertext, and the
    # `capacity - length` tail of the source is only zero for a freshly encrypted array - a
    # rotated one has data in it. The masks below therefore run over the whole storage and are
    # what makes every slot outside the padded block zero.
    flat = resize(reshape(secure_array, (length(secure_array),)), storage)

    run_length = shape[1]
    pieces = map(packing_runs(shape, padded_shape)) do run
        shift, offsets = run
        keep = falses(storage)
        for offset in offsets
            keep[(offset + 1):(offset + run_length)] .= true
        end
        mask = PlainArray([keep[i] ? 1 : 0 for i in 1:storage], context)
        # Mask first, rotate second, so the cloned junk never rotates into the data.
        circshift(flat .* mask, shift)
    end
    packed = reduce(+, pieces)

    # Fill the remaining tiles by repeated doubling. `storage ÷ block` is a power of two, so
    # this lands exactly on a full storage.
    tile_shift = block
    while tile_shift < storage
        packed += circshift(packed, tile_shift)
        tile_shift *= 2
    end

    SecureArrayPacked(packed, shape, padded_shape)
end

"""
    PlainArrayPacked(plain_array::PlainArray)

Convert an unpacked [`PlainArray`](@ref) into a [`PlainArrayPacked`](@ref). Unlike its
encrypted counterpart `SecureArrayPacked(::SecureArray)` this needs no homomorphic work at all:
the data is decoded, padded and tiled in the clear, and re-encoded.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref)
"""
PlainArrayPacked(plain_array::PlainArray) = PlainArrayPacked(collect(plain_array),
                                                             plain_array.context)

# Bring an operand into packed layout, which is where every matrix product runs. Packing a
# plaintext is free, and packing an array that is already encrypted costs one multiplicative
# level, two when the padded block spans several ciphertexts - less than the masked rotations
# of an unpacked layout cost the multiplication algorithm at any size, which is why this is
# unconditional. See `SecureArrayPacked(::SecureArray)` and `PlainArrayPacked(::PlainArray)`.
as_packed(a::Union{PlainArrayPacked, SecureArrayPacked}) = a
as_packed(a::PlainArray) = PlainArrayPacked(a)
as_packed(a::SecureArray) = SecureArrayPacked(a)

############################################################################################
# Unpacking a packed array again
############################################################################################

# The `circshift` amounts that `SecureArray(::SecureArrayPacked)` applies to the flattened
# storage: the inverses of the non-zero run shifts of the packing conversion. Unlike
# `compute_packing_shifts` this needs no `storage`, because the tiling is not undone - the data
# is simply cropped - so there are no doubling shifts here. Must be kept in sync with that
# constructor.
function compute_unpacking_shifts(shape::NTuple{N, Int},
                                  padded_shape::NTuple{N, Int}) where N
    shifts = Int[]
    for (shift, _) in packing_runs(shape, padded_shape)
        if shift != 0
            push!(shifts, -shift)
        end
    end

    unique(shifts)
end

"""
    SecureArray(secure_array::SecureArrayPacked)

Convert a [`SecureArrayPacked`](@ref) back into an unpacked, i.e. flat, [`SecureArray`](@ref) of
its unpadded shape: drop the zero padding and the tiling, so that the result is laid out exactly
like a freshly encrypted array of that shape.

This is the inverse of `SecureArrayPacked(::SecureArray)` and costs the same: the runs of
contiguous slots the padding drove apart are isolated with a plaintext mask, rotated back to
their unpadded offsets, and added up, which costs one multiplicative level - two when the padded
block spans several ciphertexts, because then the rotations are masked as well. When the first
dimension needs no padding, and for any packed vector, the unpadded data already is a contiguous
prefix of the packed block, so the conversion is a pure relabelling and costs nothing at all.

`*` applies this conversion itself to the result of a product of flat operands, so that a
product keeps the layout of its operands. Requires the rotation keys from
[`init_unpacking!`](@ref), which [`init_matrix_multiplication!`](@ref) generates as well unless
`packed = true`.

See also: [`SecureArrayPacked`](@ref), [`SecureArray`](@ref), [`init_unpacking!`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
function SecureArray(secure_array::SecureArrayPacked)
    context = secure_array.array.context
    shape = secure_array.shape
    padded_shape = secure_array.padded_shape
    _, _, storage = packed_layout(shape, slot_count(context))

    # Normalize the storage first. A matrix product returns a `(D, L)` block in
    # `max(slots, D*D)` slots, because `row_mat_times_mat` works on whole `D*D` blocks, which is
    # more than the canonical `max(slots, D*L)` of this shape - and the canonical length is the
    # one `init_unpacking!` derives its rotation keys for. The source is tiled with period
    # `prod(padded_shape)`, which divides both storages, so this only ever drops whole tiles and
    # leaves the tiling exact.
    flat = capacity(secure_array) == storage ? secure_array.array :
           resize(secure_array.array, storage)

    runs = packing_runs(shape, padded_shape)

    # A single run group that stays where it is means the unpadded data already is a contiguous
    # prefix of the packed block, so the conversion is a pure relabelling: no mask, no rotation,
    # no level. That is the case whenever the first dimension needs no padding, and for any
    # packed vector or `d`-by-1 matrix.
    if length(runs) == 1 && first(runs[1]) == 0
        return reshape(resize(flat, prod(shape)), shape)
    end

    run_length = shape[1]
    pieces = map(runs) do run
        shift, offsets = run
        # The run that starts at the unpadded offset `offset` sits at `offset + shift` in the
        # packed block, so that is where it has to be masked out before rotating it back.
        keep = falses(storage)
        for offset in offsets
            keep[(offset + shift + 1):(offset + shift + run_length)] .= true
        end
        mask = PlainArray([keep[i] ? 1 : 0 for i in 1:storage], context)
        # Mask first, rotate second, so the copies of the data in the neighbouring tiles never
        # rotate into the result.
        circshift(flat .* mask, -shift)
    end
    unpacked = reduce(+, pieces)

    # Everything outside the runs was masked away, so cropping to the unpadded length only drops
    # slots that are zero anyway.
    reshape(resize(unpacked, prod(shape)), shape)
end

"""
    PlainArray(plain_array::PlainArrayPacked)

Convert a [`PlainArrayPacked`](@ref) back into an unpacked, i.e. flat, [`PlainArray`](@ref) of its
unpadded shape. Unlike its encrypted counterpart `SecureArray(::SecureArrayPacked)` this needs no
homomorphic work at all: the data is decoded, cropped and re-encoded.

See also: [`PlainArray`](@ref), [`PlainArrayPacked`](@ref)
"""
PlainArray(plain_array::PlainArrayPacked) = PlainArray(collect(plain_array),
                                                       plain_array.array.context)

# Bring an operand back into the flat layout. The counterpart of `as_packed`: `*` packs a pair of
# flat operands on the way in and unpacks the result again on the way out, so that a product
# keeps the layout of its operands. See `SecureArray(::SecureArrayPacked)` and
# `PlainArray(::PlainArrayPacked)`.
as_unpacked(a::Union{PlainArray, SecureArray}) = a
as_unpacked(a::PlainArrayPacked) = PlainArray(a)
as_unpacked(a::SecureArrayPacked) = SecureArray(a)

"""
    init_unpacking!(context::SecureContext, private_key::PrivateKey, shape)

Generate the rotation keys required to convert a packed array of unpadded shape `shape` back into
a flat one using the `private_key`, and store them in the given `context`. `shape` is a tuple, an
integer for a vector, or an array to take the shape of.

Only the shifts the conversion actually performs are initialized, which are the inverses of the
shifts of [`init_packing!`](@ref) - and none at all when the first dimension is already a power
of two, or when `shape` is a vector, because then the unpadded data is a contiguous prefix of the
packed block.

See also: [`SecureArray`](@ref), [`PlainArray`](@ref), [`init_packing!`](@ref),
[`init_rotation!`](@ref), [`init_matrix_multiplication!`](@ref)
"""
function init_unpacking!(context::SecureContext, private_key::PrivateKey,
                         shape::NTuple{N, Int}) where N
    if any(<(1), shape)
        throw(DimensionMismatch("shape must not be empty, got $shape"))
    end
    padded_shape, _, storage = packed_layout(shape, slot_count(context))

    shifts = compute_unpacking_shifts(shape, padded_shape)
    # The conversion performs no rotation at all, so there is nothing to generate. Calling
    # `init_rotation!` with an empty shift list would still generate one key, see
    # `compute_rotation_indices_1d`.
    if isempty(shifts)
        return nothing
    end

    init_rotation!(context, private_key, storage, shifts...)
end

init_unpacking!(context::SecureContext, private_key::PrivateKey, n::Integer) =
    init_unpacking!(context, private_key, (Int(n),))

init_unpacking!(context::SecureContext, private_key::PrivateKey,
                a::Union{PlainArray, SecureArray}) = init_unpacking!(context, private_key,
                                                                     size(a))

"""
    init_packing!(context::SecureContext, private_key::PrivateKey, shape)

Generate the rotation keys required to convert an unpacked array of shape `shape` into a packed
one using the `private_key`, and store them in the given `context`. `shape` is a tuple, an
integer for a vector, or an array to take the shape of.

Only the shifts the conversion actually performs are initialized. For a `(d, l)` matrix those
are the `l - 1` shifts that drive the columns apart, plus one shift per tiling step - and none
at all when the first dimension is already a power of two and the padded block fills its
storage.

See also: [`SecureArrayPacked`](@ref), [`PlainArrayPacked`](@ref), [`init_rotation!`](@ref),
[`init_matrix_multiplication!`](@ref)
"""
function init_packing!(context::SecureContext, private_key::PrivateKey,
                       shape::NTuple{N, Int}) where N
    if any(<(1), shape)
        throw(DimensionMismatch("shape must not be empty, got $shape"))
    end
    padded_shape, _, storage = packed_layout(shape, slot_count(context))

    shifts = compute_packing_shifts(shape, padded_shape, storage)
    # The conversion performs no rotation at all, so there is nothing to generate. Calling
    # `init_rotation!` with an empty shift list would still generate one key, see
    # `compute_rotation_indices_1d`.
    if isempty(shifts)
        return nothing
    end

    init_rotation!(context, private_key, storage, shifts...)
end

init_packing!(context::SecureContext, private_key::PrivateKey, n::Integer) =
    init_packing!(context, private_key, (Int(n),))

init_packing!(context::SecureContext, private_key::PrivateKey,
              a::Union{PlainArray, SecureArray}) = init_packing!(context, private_key, size(a))

"""
    encrypt(plain_array::PlainArrayPacked, public_key::PublicKey)

Encrypt `plain_array` into a [`SecureArrayPacked`](@ref) using the `public_key`, preserving
the packed layout.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref), [`decrypt`](@ref)
"""
function encrypt(plain_array::PlainArrayPacked, public_key::PublicKey)
    SecureArrayPacked(encrypt(plain_array.array, public_key), plain_array.shape,
                      plain_array.padded_shape)
end

"""
    decrypt(secure_array::SecureArrayPacked, private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and return the resulting
[`PlainArrayPacked`](@ref). Use `collect` on the result to get the data cropped back to its
unpadded shape.

See also: [`SecureArrayPacked`](@ref), [`PlainArrayPacked`](@ref), [`decrypt!`](@ref)
"""
function decrypt(secure_array::SecureArrayPacked, private_key::PrivateKey)
    PlainArrayPacked(decrypt(secure_array.array, private_key), secure_array.shape,
                     secure_array.padded_shape)
end

"""
    decrypt!(plain_array::PlainArrayPacked, secure_array::SecureArrayPacked,
             private_key::PrivateKey)

Decrypt `secure_array` using the `private_key` and store the result in `plain_array`.

See also: [`SecureArrayPacked`](@ref), [`PlainArrayPacked`](@ref), [`decrypt`](@ref)
"""
function decrypt!(plain_array::PlainArrayPacked, secure_array::SecureArrayPacked,
                  private_key::PrivateKey)
    decrypt!(plain_array.array, secure_array.array, private_key)

    plain_array
end

"""
    level(a::Union{PlainArrayPacked, SecureArrayPacked})

Return the number of scalings, referred to as the level, performed over `a`.

See also: [`PlainArrayPacked`](@ref), [`SecureArrayPacked`](@ref)
"""
level(a::Union{PlainArrayPacked, SecureArrayPacked}) = level(a.array)
