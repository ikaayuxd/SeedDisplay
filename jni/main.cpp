/**
 * SeedDisplay — MCPE Bedrock Mod
 *
 * Uses libBedrockTools.so (GlossHook + ImGui bundled) to:
 *  1. Hook Level::getSeed() via GlossHookByName / GlossHook
 *  2. Hook eglSwapBuffers via GlossPltHook
 *  3. Render seed as an ImGui overlay every frame
 *
 * Architecture: arm64-v8a  (aarch64)
 * Target:       MCPE / Minecraft Bedrock (any recent version)
 */

#include <jni.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <pthread.h>
#include <unistd.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>

// ── libBedrockTools public API ───────────────────────────────────────────────
// These are all confirmed exported symbols from libBedrockTools.so
extern "C" {
    // GlossHook — inline/function hooking
    bool    GlossInit(bool hookLinker);
    void*   GlossHook(void* func, void* hook, void** orig);
    void*   GlossHookByName(const char* lib, const char* symbol,
                             void* hook, void** orig);
    void*   GlossPltHook(const char* lib, const char* symbol,
                          void* hook, void** orig);
    void*   GlossSymbol(const char* lib, const char* symbol);

    // Memory helpers (also exported by BedrockTools)
    bool    WriteMemory(void* addr, const void* data, size_t size);
    bool    ReadMemory(void* addr, void* buf, size_t size);
    void    CodePatch(void* addr, const uint8_t* patch, size_t size);
}

// ── ImGui — bundled inside libBedrockTools ───────────────────────────────────
#include "imgui/imgui.h"
#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_android.h"

// ── Logging ──────────────────────────────────────────────────────────────────
#define TAG  "SeedDisplay"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── Global state ──────────────────────────────────────────────────────────────
static int64_t  g_seed       = 0;
static bool     g_hasSeed    = false;
static bool     g_imguiInit  = false;
static bool     g_isServer   = false;

// ─────────────────────────────────────────────────────────────────────────────
// HOOK 1 — Level::getSeed()
//   Mangled: _ZNK5Level7getSeedEv
//   Signature: int64_t Level::getSeed() const
// ─────────────────────────────────────────────────────────────────────────────
typedef int64_t (*FnGetSeed)(void*);
static FnGetSeed orig_getSeed = nullptr;

static int64_t hook_getSeed(void* thiz) {
    int64_t seed  = orig_getSeed(thiz);
    g_seed        = seed;
    g_hasSeed     = true;
    LOGD("getSeed() -> %lld", (long long)seed);
    return seed;
}

// ─────────────────────────────────────────────────────────────────────────────
// HOOK 2 — ServerNetworkHandler ctor (detect server/multiplayer world)
// ─────────────────────────────────────────────────────────────────────────────
typedef void (*FnSNHCtor)(void*);
static FnSNHCtor orig_snhCtor = nullptr;

static void hook_snhCtor(void* thiz) {
    g_isServer = true;
    LOGD("ServerNetworkHandler created — server world detected");
    orig_snhCtor(thiz);
}

// ─────────────────────────────────────────────────────────────────────────────
// ImGui overlay draw
// ─────────────────────────────────────────────────────────────────────────────
static void drawOverlay() {
    if (!g_hasSeed) return;

    ImGui::SetNextWindowPos({10.f, 10.f}, ImGuiCond_Always);
    ImGui::SetNextWindowSize({0.f, 0.f});
    ImGui::SetNextWindowBgAlpha(0.60f);

    constexpr ImGuiWindowFlags kFlags =
        ImGuiWindowFlags_NoDecoration    |
        ImGuiWindowFlags_NoInputs         |
        ImGuiWindowFlags_NoMove           |
        ImGuiWindowFlags_NoSavedSettings  |
        ImGuiWindowFlags_NoNav            |
        ImGuiWindowFlags_AlwaysAutoResize;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 7.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  {10.f, 8.f});
    ImGui::PushStyleColor(ImGuiCol_WindowBg,  {0.05f, 0.05f, 0.08f, 0.60f});
    ImGui::PushStyleColor(ImGuiCol_Separator, {0.30f, 0.30f, 0.40f, 1.00f});

    if (ImGui::Begin("##SeedDisplay", nullptr, kFlags)) {
        ImGui::TextColored({0.4f, 0.85f, 1.0f, 1.0f}, "Seed Display");
        ImGui::Separator();
        ImGui::Spacing();

        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)g_seed);
        ImGui::Text("Seed:");
        ImGui::SameLine(58.f);
        ImGui::TextColored({1.0f, 0.85f, 0.2f, 1.0f}, "%s", buf);

        ImGui::Spacing();
        if (g_isServer)
            ImGui::TextColored({0.4f, 1.0f, 0.5f,  1.0f}, "[Server World]");
        else
            ImGui::TextColored({0.75f,0.75f,0.85f, 1.0f}, "[Local World]");
    }
    ImGui::End();

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

// ─────────────────────────────────────────────────────────────────────────────
// HOOK 3 — eglSwapBuffers  (called every rendered frame)
// ─────────────────────────────────────────────────────────────────────────────
typedef EGLBoolean (*FnSwap)(EGLDisplay, EGLSurface);
static FnSwap orig_eglSwap = nullptr;

static EGLBoolean hook_eglSwap(EGLDisplay dpy, EGLSurface surf) {

    if (!g_imguiInit) {
        // Must be initialised on the GL thread (here, first swap call)
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();

        ImGuiIO& io = ImGui::GetIO();
        EGLint w = 0, h = 0;
        eglQuerySurface(dpy, surf, EGL_WIDTH,  &w);
        eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
        io.DisplaySize = {(float)(w > 0 ? w : 1280),
                          (float)(h > 0 ? h : 720)};

        ImGui::StyleColorsDark();
        ImGui_ImplOpenGL3_Init("#version 300 es");

        g_imguiInit = true;
        LOGD("ImGui initialised (%dx%d)", w, h);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
    drawOverlay();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    return orig_eglSwap(dpy, surf);
}

// ─────────────────────────────────────────────────────────────────────────────
// Init thread — runs after library load, sets up all hooks
// ─────────────────────────────────────────────────────────────────────────────
static void* modInit(void*) {
    sleep(2);  // give libminecraftpe.so time to fully load

    // Initialise GlossHook (no linker hook needed)
    if (!GlossInit(false)) {
        LOGE("GlossInit failed — aborting");
        return nullptr;
    }
    LOGD("GlossInit OK");

    // ── Hook Level::getSeed ──────────────────────────────────────────────────
    // Try symbol-name hook first (most portable across MCPE updates)
    const char* kSeedSym = "_ZNK5Level7getSeedEv";
    bool ok = GlossHookByName("libminecraftpe.so", kSeedSym,
                               (void*)hook_getSeed, (void**)&orig_getSeed) != nullptr;
    if (!ok) {
        // Fallback: resolve then hook by address
        void* addr = GlossSymbol("libminecraftpe.so", kSeedSym);
        if (addr) {
            GlossHook(addr, (void*)hook_getSeed, (void**)&orig_getSeed);
            LOGD("getSeed hooked via GlossHook (addr fallback)");
        } else {
            LOGE("getSeed symbol not found in libminecraftpe.so");
        }
    } else {
        LOGD("getSeed hooked via GlossHookByName");
    }

    // ── Hook ServerNetworkHandler ctor (server detection) ────────────────────
    // Symbol varies by MCPE version — try common mangled names
    const char* kSNH[] = {
        "_ZN20ServerNetworkHandlerC1ERN4Core15StoragePathTreeERN3Bedrock8PlatformEP13NetEventCallbackR11PermissionDBypas",
        "_ZN20ServerNetworkHandlerC2ERKSt10shared_ptrI10LevelStorEP21RakNetNetworkHandlerN4Core14SemVer16Version4InfoE",
        "_ZN20ServerNetworkHandlerC1Ev",
        nullptr
    };
    for (int i = 0; kSNH[i]; i++) {
        void* a = GlossSymbol("libminecraftpe.so", kSNH[i]);
        if (a) {
            GlossHook(a, (void*)hook_snhCtor, (void**)&orig_snhCtor);
            LOGD("ServerNetworkHandler ctor hooked (variant %d)", i);
            break;
        }
    }

    // ── Hook eglSwapBuffers ──────────────────────────────────────────────────
    // GlossPltHook patches the PLT entry inside libminecraftpe.so — cleaner
    // than hooking the actual EGL function globally
    bool swapOk = GlossPltHook("libminecraftpe.so", "eglSwapBuffers",
                                 (void*)hook_eglSwap,
                                 (void**)&orig_eglSwap) != nullptr;
    if (!swapOk) {
        // Direct hook fallback
        GlossHook((void*)eglSwapBuffers,
                   (void*)hook_eglSwap, (void**)&orig_eglSwap);
        LOGD("eglSwapBuffers hooked via direct GlossHook");
    } else {
        LOGD("eglSwapBuffers hooked via GlossPltHook");
    }

    LOGD("SeedDisplay fully initialised");
    return nullptr;
}

// ── Library constructor — called when .so is injected ────────────────────────
__attribute__((constructor))
static void onLoad() {
    LOGD("SeedDisplay .so loaded");
    pthread_t tid;
    pthread_create(&tid, nullptr, modInit, nullptr);
    pthread_detach(tid);
}
