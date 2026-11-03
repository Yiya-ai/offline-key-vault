"""Execute Argon2 lanes sequentially on WASM, preserving the specified KDF."""
from argon2.low_level import core, ffi, lib, Type


def hash_secret_raw(secret, salt, time_cost, memory_cost, parallelism, hash_len, type, version=19):
    # Lanes affect the hash; threads only affect execution. Never lower lanes.
    if (not isinstance(secret, bytes) or len(secret) > 1024 or not isinstance(salt, bytes)
            or not 8 <= len(salt) <= 64 or version != 19 or not isinstance(type, Type)
            or not all(isinstance(x, int) for x in (time_cost, memory_cost, parallelism, hash_len))
            or not 1 <= parallelism <= 16 or not 8 * parallelism <= memory_cost <= 262144
            or not 1 <= time_cost <= 32 or time_cost * memory_cost > 1048576 or not 4 <= hash_len <= 80):
        raise ValueError('Argon2 参数超过资源限制')
    pwd = ffi.new('uint8_t[]', secret)
    salt_buf = ffi.new('uint8_t[]', salt)
    output = ffi.new('uint8_t[]', hash_len)
    context = ffi.new('argon2_context *', {
        'out': output, 'outlen': hash_len, 'pwd': pwd, 'pwdlen': len(secret),
        'salt': salt_buf, 'saltlen': len(salt), 'secret': ffi.NULL, 'secretlen': 0,
        'ad': ffi.NULL, 'adlen': 0, 't_cost': time_cost, 'm_cost': memory_cost,
        'lanes': parallelism, 'threads': 1, 'version': version,
        'allocate_cbk': ffi.NULL, 'free_cbk': ffi.NULL, 'flags': lib.ARGON2_DEFAULT_FLAGS,
    })
    try:
        if core(context, type.value) != lib.ARGON2_OK:
            raise ValueError('Argon2 计算未完成')
        return bytes(ffi.buffer(output, hash_len))
    finally:
        for buf, length in ((pwd, len(secret)), (salt_buf, len(salt)), (output, hash_len)):
            ffi.buffer(buf, length)[:] = b'\0' * length
