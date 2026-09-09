"""Current-user Windows DPAPI storage; no network or interactive security prompts."""
import ctypes
from ctypes import wintypes
import os

PREFIX = 'aegis-dpapi-v1:'


class Blob(ctypes.Structure):
    _fields_ = [('size', wintypes.DWORD), ('data', ctypes.POINTER(ctypes.c_ubyte))]


def _transform(data, decrypt):
    if os.name != 'nt':
        raise RuntimeError('Credential protection requires Windows.')
    crypt = ctypes.WinDLL('crypt32', use_last_error=True)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    function = crypt.CryptUnprotectData if decrypt else crypt.CryptProtectData
    function.argtypes = [ctypes.POINTER(Blob), ctypes.c_void_p, ctypes.c_void_p,
                         ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(Blob)]
    function.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = Blob(len(data), buffer)
    target = Blob()
    try:
        if not function(ctypes.byref(source), None, None, None, None, 1, ctypes.byref(target)):
            raise OSError('Windows could not ' + ('decrypt' if decrypt else 'protect') +
                          ' the credential for this account (error ' + str(ctypes.get_last_error()) + ').')
        return ctypes.string_at(target.data, target.size)
    finally:
        if target.data:
            if decrypt:
                ctypes.memset(target.data, 0, target.size)
            kernel.LocalFree(target.data)
        ctypes.memset(buffer, 0, len(data))


def protect_secret(value):
    return PREFIX + _transform(value.encode('utf-8'), False).hex()


def unprotect_secret(value):
    if not value.startswith(PREFIX):
        if value.startswith('aegis-dpapi-'):
            raise ValueError('Unsupported protected credential version.')
        return value
    try:
        raw = bytes.fromhex(value[len(PREFIX):])
        if not raw or len(raw) > 65536:
            raise ValueError('Invalid protected credential size.')
        return _transform(raw, True).decode('utf-8')
    except ValueError:
        raise ValueError('Invalid protected credential.') from None
