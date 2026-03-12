# SeedDisplay — MCPE Bedrock Mod

Displays the world / server seed as a floating overlay, using **libBedrockTools.so**
as the hooking + rendering backend (same as the reference .so).

```
┌──────────────────┐
│ Seed Display     │
│────────────────  │
│ Seed: 123456789  │
│ [Local World]    │
└──────────────────┘
```

---

## How it works (learned from libBedrockTools)

From analysing `libBedrockTools.so`:

| What we found | What it means |
|---|---|
| `GlossInit`, `GlossHook`, `GlossHookByName`, `GlossPltHook`, `GlossSymbol` | GlossHook is the hooking engine — used for both inline and PLT hooks |
| `MSHookFunction`, `MSHookThumb`, `A64HookFunction` | Substrate-compatible hooks also bundled — for legacy compat |
| `ImGui` (full), `imgui_impl_opengl3`, `imgui_impl_android` | ImGui is embedded — overlay rendering is done via OpenGL ES |
| `eglGetCurrentContext`, `eglQuerySurface` | EGL is used to find display size for ImGui |
| `WriteMemory`, `ReadMemory`, `CodePatch`, `MemoryFill` | Memory patching utilities are also exported |
| `libminecraftpe.so` string | Hooks target this library by name |
| `##overlayOpacity`, `Seed` | ImGui window IDs / labels used in overlay |
| NDK `r26b`, `arm64-v8a`, Android API 21+ | Build config |

Our mod calls exactly these APIs — no reimplementation needed.

---

## Project structure

```
SeedDisplay/
├── jni/
│   ├── main.cpp          ← mod source (hooks + ImGui overlay)
│   ├── Android.mk        ← links against libBedrockTools.so
│   ├── Application.mk    ← arm64-v8a + armeabi-v7a, API 21
│   ├── imgui/            ← ImGui headers only (no .cpp needed)
│   └── libs/
│       ├── arm64-v8a/libBedrockTools.so    ← your copy of the .so
│       └── armeabi-v7a/libBedrockTools.so  ← (optional 32-bit)
└── .github/workflows/build.yml
```

---

## Building

### Option A — GitHub Actions (no local setup)

1. Fork/push this repo to GitHub
2. Place `libBedrockTools.so` in `jni/libs/arm64-v8a/`
3. Actions → **Build SeedDisplay** → Run workflow
4. Download `libSeedDisplay.so` from artifacts

### Option B — Local (Linux / WSL)

```bash
# Requires: Android NDK r26b, ndk-build in PATH

git clone https://github.com/YOU/SeedDisplay && cd SeedDisplay

# Place libBedrockTools.so:
mkdir -p jni/libs/arm64-v8a
cp /path/to/libBedrockTools.so jni/libs/arm64-v8a/

# Get ImGui headers (no .cpp needed — already in BedrockTools):
mkdir -p jni/imgui
# download imgui.h, imgui_internal.h, imconfig.h,
#          imgui_impl_opengl3.h, imgui_impl_android.h
# into jni/imgui/

ndk-build NDK_PROJECT_PATH=. \
          APP_BUILD_SCRIPT=jni/Android.mk \
          NDK_APPLICATION_MK=jni/Application.mk -j4

# Output: libs/arm64-v8a/libSeedDisplay.so
```

---

## Installing

Inject `libSeedDisplay.so` alongside `libBedrockTools.so` into
`com.mojang.minecraftpe` using any .so injector (requires root or Zygisk).

Both `.so` files must be present — `libSeedDisplay.so` loads `libBedrockTools.so`
at runtime via the dynamic linker.

---

## Notes

- Hooks `Level::getSeed()` by mangled symbol name — works across MCPE versions
  as long as the class name doesn't change
- Falls back to address-based hook if symbol lookup fails
- Detects server worlds by hooking `ServerNetworkHandler` constructor
- Overlay renders at top-left corner, 60% opacity, yellow seed text
