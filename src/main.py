import ctypes

# Load the DLL
lib = ctypes.CDLL("./crypto_engine/secure_objects.dll")


make_secure = getattr(lib, "make_secure")

s = make_secure("hello")
print(s)
