# common

- Shared source files (common library - lists, memory helpers, etc...);
- This directory is typically symlinked into other projects.
- Also contains sources for a C unit testing framework - munit.h and munit.c
- munit.h and munit.c are fork of https://nemequ.github.io/munit/

## Building the `-fbounds-safety` toolchain

Full `-fbounds-safety` enforcement is not yet in upstream LLVM. The working
implementation lives in the [swiftlang Clang fork](https://github.com/swiftlang/llvm-project).
Requires `cmake` and `ninja-build`.

```bash
# Clone (blobless shallow clone, ~2 min)
git clone --depth 1 --branch stable/21.x --filter=blob:none \
  https://github.com/swiftlang/llvm-project.git /home/node/llvm-bs

# Configure (Clang only, Release, host architecture)
cmake -G Ninja -S /home/node/llvm-bs/llvm -B /home/node/llvm-bs/build \
  -DLLVM_ENABLE_PROJECTS="clang" \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_TARGETS_TO_BUILD="Native" \
  -DLLVM_INCLUDE_TESTS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_DOCS=OFF

# Build (~15 min on 8 cores)
cmake --build /home/node/llvm-bs/build --target clang -- -j$(nproc)
```

The resulting Clang binary accepts `-fbounds-safety`. The `BOUNDS_SAFETY`
Makefile flag wires this into the build:

```bash
make CC=/home/node/llvm-bs/build/bin/clang BOUNDS_SAFETY=y
```

## Bounds-safety annotations

Selected modules are annotated with `-fbounds-safety` attributes
(`__counted_by`, `__sized_by`, etc.) on pointer/size parameter pairs.
The compatibility header `bounds_safety.h` includes `<ptrcheck.h>` from
the swiftlang Clang fork when available, falling back to no-op
definitions on GCC and stock Clang. Annotated code builds everywhere.

**Annotated modules:** `hex.c/h` (pilot). Listed in `BOUNDS_SAFE_SRCS`
in the Makefile. When `BOUNDS_SAFETY=y`, only these files are compiled
with `-fbounds-safety`; all other files compile normally. To annotate a
new module, add its `.c` filename to `BOUNDS_SAFE_SRCS`.

```bash
# Build with bounds enforcement on annotated modules
make CC=/home/node/llvm-bs/build/bin/clang BOUNDS_SAFETY=y
```
