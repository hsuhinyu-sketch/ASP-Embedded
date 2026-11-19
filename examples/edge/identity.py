"""Local example issuer: Ed25519 through system libcrypto; never used by the Gateway verifier."""
import ctypes
import ctypes.util


def ed25519(seed, message=None):
    if len(seed) != 32:
        raise ValueError('Ed25519 seed must contain exactly 32 bytes')
    crypto = ctypes.CDLL(ctypes.util.find_library('crypto') or 'libcrypto.so.3')
    pointer, size = ctypes.c_void_p, ctypes.c_size_t
    signatures = {
        'EVP_PKEY_new_raw_private_key': (pointer, [ctypes.c_int, pointer, pointer, size]),
        'EVP_PKEY_get_raw_public_key': (ctypes.c_int, [pointer, pointer, ctypes.POINTER(size)]),
        'EVP_PKEY_free': (None, [pointer]),
        'EVP_MD_CTX_new': (pointer, []),
        'EVP_MD_CTX_free': (None, [pointer]),
        'EVP_DigestSignInit': (ctypes.c_int, [pointer, pointer, pointer, pointer, pointer]),
        'EVP_DigestSign': (ctypes.c_int, [pointer, pointer, ctypes.POINTER(size), pointer, size]),
    }
    for name, (result, arguments) in signatures.items():
        function = getattr(crypto, name)
        function.restype, function.argtypes = result, arguments
    def check(value):
        if value != 1:
            raise RuntimeError('libcrypto Ed25519 operation failed')
    key = crypto.EVP_PKEY_new_raw_private_key(1087, None, seed, len(seed))
    if not key:
        raise RuntimeError('libcrypto could not load the Ed25519 key')
    try:
        if message is None:
            output, length = ctypes.create_string_buffer(32), size(32)
            check(crypto.EVP_PKEY_get_raw_public_key(key, output, ctypes.byref(length)))
        else:
            context = crypto.EVP_MD_CTX_new()
            if not context:
                raise RuntimeError('libcrypto could not allocate the signing context')
            try:
                check(crypto.EVP_DigestSignInit(context, None, None, None, key))
                output, length = ctypes.create_string_buffer(64), size(64)
                check(crypto.EVP_DigestSign(context, output, ctypes.byref(length), message, len(message)))
            finally:
                crypto.EVP_MD_CTX_free(context)
        return output.raw[:length.value]
    finally:
        crypto.EVP_PKEY_free(key)
