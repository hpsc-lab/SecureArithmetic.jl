# Add
Base.:+(sv1::SecureVector, sv2::SecureVector) = add(sv1, sv2)
Base.:+(sv::SecureVector, pv::PlainVector) = add(sv, pv)
Base.:+(pv::PlainVector, sv::SecureVector) = add(sv, pv)
Base.:+(sv::SecureVector, scalar::Real) = add(sv, scalar)
Base.:+(scalar::Real, sv::SecureVector) = add(sv, scalar)

# Subtract
Base.:-(sv1::SecureVector, sv2::SecureVector) = subtract(sv1, sv2)
Base.:-(sv::SecureVector, pv::PlainVector) = subtract(sv, pv)
Base.:-(pv::PlainVector, sv::SecureVector) = subtract(pv, sv)
Base.:-(sv::SecureVector, scalar::Real) = subtract(sv, scalar)
Base.:-(scalar::Real, sv::SecureVector) = subtract(scalar, sv)

# Negate
Base.:-(sv::SecureVector) = negate(sv)

# Multiply
Base.:*(sv1::SecureVector, sv2::SecureVector) = multiply(sv1, sv2)
Base.:*(sv::SecureVector, pv::PlainVector) = multiply(sv, pv)
Base.:*(pv::PlainVector, sv::SecureVector) = multiply(sv, pv)
Base.:*(sv::SecureVector, scalar::Real) = multiply(sv, scalar)
Base.:*(scalar::Real, sv::SecureVector) = multiply(sv, scalar)

# Circular shift
Base.circshift(sv::SecureVector, shift::Integer) = rotate(sv, shift)
