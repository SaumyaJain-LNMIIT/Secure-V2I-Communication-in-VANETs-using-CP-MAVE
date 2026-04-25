"""
vansec/_bootstrap.py — Windows DLL fix for fastecdsa.

On Python 3.10+ / Windows, the libgmp-10.dll shipped with fastecdsa
is not found automatically because of security-restricted DLL loading.

This module must be imported BEFORE any fastecdsa submodule that uses
C extensions (point, curvemath, _ecdsa).

Usage: ``import vansec._bootstrap`` as the first import in any entry point.
"""
import sys
import os

if sys.platform == "win32":
    try:
        import fastecdsa as _fe
        _fe_dir = os.path.dirname(os.path.abspath(_fe.__file__))
        _gmp = os.path.join(_fe_dir, "libgmp-10.dll")
        if os.path.exists(_gmp):
            import ctypes
            ctypes.CDLL(_gmp)
    except Exception:
        pass
