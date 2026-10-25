from setuptools import Extension, setup

# The native GF(2)[x] arithmetic is optional: without a C compiler, HyBolt
# installs anyway and hybolt.utils.galois falls back to pure Python.
setup(
    ext_modules=[
        Extension("hybolt.utils._gf2", ["hybolt/utils/_gf2.c"], optional=True),
    ]
)
