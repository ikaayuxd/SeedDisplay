/**
 * SeedDisplay — MCPE Bedrock Mod (DEBUG VERSION)
 * Scans libminecraftpe.so for seed-related symbols and logs them
 * so we can find the correct function to hook.
 */

#include <jni.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES3/gl3.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <link.h>
#include <sys/mman.h>

// ── libBedrockTools public API ───────────────────────────────────────────────
extern "C" {
    bool    GlossInit(bool hookLinker);
    void*   GlossHook(void* func, void* hook, void** orig);
    void*   GlossHookByName(const char* lib, const char* symbol,
                             void* hook, void** orig);
    void*   GlossPltHook(const char* lib, const char* symbol,
                          void* hook, void** orig);
    void*   GlossSymbol(const char* lib, const char* symbol);
}

#include "imgui/imgui.h"
#include "imgui/imgui_impl_opengl3.h"
#include "imgui/imgui_impl_android.h"

#define TAG  "SeedDisplay"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ── State ─────────────────────────────────────────────────────────────────────
static int64_t  g_seed        = 0;
static bool     g_hasSeed     = false;
static bool     g_imguiInit   = false;
static bool     g_isServer    = false;
static char     g_statusMsg[256] = "Searching for seed symbol...";

// ── Possible seed symbol names across MCPE versions ──────────────────────────
static const char* kSeedSymbols[] = {
    // Common variants found across MCPE versions
    "_ZNK5Level7getSeedEv",
    "_ZN5Level7getSeedEv",
    "_ZNK5Level4seedEv",
    "_ZN5Level4seedEv",
    "_ZNK9LevelData7getSeedEv",
    "_ZN9LevelData7getSeedEv",
    "_ZNK9LevelData4seedEv",
    "_ZNK11LevelStorage7getSeedEv",
    "_ZNK5Level13getLevelSeedEv",
    "_ZN5Level13getLevelSeedEv",
    "_ZNK13ServerLevel7getSeedEv",
    "_ZN13ServerLevel7getSeedEv",
    nullptr
};

// ── Hook: Level::getSeed (tried for each symbol above) ───────────────────────
typedef int64_t (*FnGetSeed)(void*);
static FnGetSeed orig_getSeed = nullptr;

static int64_t hook_getSeed(void* thiz) {
    int64_t seed = orig_getSeed(thiz);
    g_seed    = seed;
    g_hasSeed = true;
    snprintf(g_statusMsg, sizeof(g_statusMsg), "Seed hooked OK");
    LOGD("getSeed() -> %lld", (long long)seed);
    return seed;
}

// ── Scan /proc/self/maps for libminecraftpe base ──────────────────────────────
static uintptr_t getLibBase(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname) && strstr(line, "r-xp")) {
            base = (uintptr_t)strtoull(line, nullptr, 16);
            break;
        }
    }
    fclose(f);
    return base;
}

// ── Scan ELF symbol table for any symbol containing "seed" or "Seed" ─────────
static void scanForSeedSymbols(const char* libname) {
    // Use dlopen to get handle then walk ELF manually
    void* handle = dlopen(libname, RTLD_NOLOAD | RTLD_NOW);
    if (!handle) {
        LOGE("dlopen(%s) failed: %s", libname, dlerror());
        return;
    }

    // Walk /proc/self/maps to find the loaded .so
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) { dlclose(handle); return; }

    uintptr_t base = 0;
    char path[256];
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname)) {
            base = (uintptr_t)strtoull(line, nullptr, 16);
            break;
        }
    }
    fclose(f);

    if (!base) {
        LOGE("Could not find base for %s", libname);
        dlclose(handle);
        return;
    }

    LOGD("libminecraftpe.so base: 0x%llx", (unsigned long long)base);

    // Parse ELF header
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E') {
        LOGE("Bad ELF magic at base");
        dlclose(handle);
        return;
    }

    // Find dynamic symbol table
    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn*  dyn  = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
            break;
        }
    }

    if (!dyn) { LOGE("No PT_DYNAMIC"); dlclose(handle); return; }

    Elf64_Sym*  symtab  = nullptr;
    const char* strtab  = nullptr;
    size_t      symcnt  = 0;

    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if      (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB) strtab = (const char*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_SYMENT) {} // 24 bytes each
    }

    if (!symtab || !strtab) {
        LOGE("Could not find symtab/strtab");
        dlclose(handle);
        return;
    }

    // Scan up to 500000 symbols looking for "seed" or "Seed"
    int found = 0;
    for (int i = 0; i < 500000 && found < 20; i++) {
        const char* name = strtab + symtab[i].st_name;
        if ((strstr(name, "seed") || strstr(name, "Seed")) &&
             symtab[i].st_value != 0) {
            LOGD("SEED SYMBOL [%d]: %s  addr=0x%llx",
                 i, name, (unsigned long long)(base + symtab[i].st_value));
            found++;
        }
    }

    if (found == 0) LOGD("No seed symbols found in first 500k entries");

    dlclose(handle);
}

// ── ImGui overlay ─────────────────────────────────────────────────────────────
static void drawOverlay() {
    ImGui::SetNextWindowPos({10.f, 10.f}, ImGuiCond_Always);
    ImGui::SetNextWindowSize({0.f, 0.f});
    ImGui::SetNextWindowBgAlpha(0.70f);

    constexpr ImGuiWindowFlags kFlags =
        ImGuiWindowFlags_NoDecoration    |
        ImGuiWindowFlags_NoInputs        |
        ImGuiWindowFlags_NoMove          |
        ImGuiWindowFlags_NoSavedSettings |
        ImGuiWindowFlags_NoNav           |
        ImGuiWindowFlags_AlwaysAutoResize;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 7.f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding,  {10.f, 8.f});
    ImGui::PushStyleColor(ImGuiCol_WindowBg,  {0.05f, 0.05f, 0.08f, 0.70f});
    ImGui::PushStyleColor(ImGuiCol_Separator, {0.30f, 0.30f, 0.40f, 1.00f});

    if (ImGui::Begin("##SeedDisplay", nullptr, kFlags)) {
        ImGui::TextColored({0.4f, 0.85f, 1.0f, 1.0f}, "Seed Display");
        ImGui::Separator();
        ImGui::Spacing();

        if (g_hasSeed) {
            char buf[32];
            snprintf(buf, sizeof(buf), "%lld", (long long)g_seed);
            ImGui::Text("Seed:");
            ImGui::SameLine(58.f);
            ImGui::TextColored({1.0f, 0.85f, 0.2f, 1.0f}, "%s", buf);

            ImGui::Spacing();
            if (g_isServer)
                ImGui::TextColored({0.4f,  1.0f,  0.5f,  1.0f}, "[Server World]");
            else
                ImGui::TextColored({0.75f, 0.75f, 0.85f, 1.0f}, "[Local World]");
        } else {
            // Show status while searching
            ImGui::TextColored({1.0f, 0.6f, 0.2f, 1.0f}, "%s", g_statusMsg);
            ImGui::Spacing();
            ImGui::TextColored({0.6f, 0.6f, 0.6f, 1.0f}, "Check logcat:");
            ImGui::TextColored({0.6f, 0.6f, 0.6f, 1.0f}, "tag SeedDisplay");
        }
    }
    ImGui::End();

    ImGui::PopStyleColor(2);
    ImGui::PopStyleVar(2);
}

// ── Hook: eglSwapBuffers ──────────────────────────────────────────────────────
typedef EGLBoolean (*FnSwap)(EGLDisplay, EGLSurface);
static FnSwap orig_eglSwap = nullptr;

static EGLBoolean hook_eglSwap(EGLDisplay dpy, EGLSurface surf) {
    if (!g_imguiInit) {
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
        LOGD("ImGui init %dx%d", w, h);
    }

    ImGui_ImplOpenGL3_NewFrame();
    ImGui::NewFrame();
    drawOverlay();
    ImGui::Render();
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

    return orig_eglSwap(dpy, surf);
}

// ── Init thread ───────────────────────────────────────────────────────────────
static void* modInit(void*) {
    sleep(3);

    LOGD("=== SeedDisplay DEBUG init ===");

    if (!GlossInit(false)) {
        LOGE("GlossInit failed");
        snprintf(g_statusMsg, sizeof(g_statusMsg), "GlossInit FAILED");
        return nullptr;
    }
    LOGD("GlossInit OK");

    // Try all known seed symbol names
    bool hooked = false;
    for (int i = 0; kSeedSymbols[i] != nullptr; i++) {
        void* addr = GlossSymbol("libminecraftpe.so", kSeedSymbols[i]);
        LOGD("Symbol [%d] %s -> %p", i, kSeedSymbols[i], addr);
        if (addr && !hooked) {
            GlossHook(addr, (void*)hook_getSeed, (void**)&orig_getSeed);
            snprintf(g_statusMsg, sizeof(g_statusMsg), "Hooked: %s", kSeedSymbols[i]);
            LOGD("Hooked via: %s", kSeedSymbols[i]);
            hooked = true;
        }
    }

    if (!hooked) {
        LOGE("No seed symbol found — scanning ELF...");
        snprintf(g_statusMsg, sizeof(g_statusMsg), "Scanning ELF for seed...");
        scanForSeedSymbols("libminecraftpe.so");
        snprintf(g_statusMsg, sizeof(g_statusMsg), "See logcat for symbols");
    }

    // Hook eglSwapBuffers for overlay
    bool swapOk = GlossPltHook("libminecraftpe.so", "eglSwapBuffers",
                                (void*)hook_eglSwap,
                                (void**)&orig_eglSwap) != nullptr;
    if (!swapOk) {
        GlossHook((void*)eglSwapBuffers,
                  (void*)hook_eglSwap, (void**)&orig_eglSwap);
        LOGD("eglSwapBuffers: direct hook");
    } else {
        LOGD("eglSwapBuffers: PLT hook");
    }

    LOGD("=== init done, hooked=%d ===", (int)hooked);
    return nullptr;
}

// ── Entry point ───────────────────────────────────────────────────────────────
__attribute__((constructor))
static void onLoad() {
    LOGD("SeedDisplay loaded");
    pthread_t tid;
    pthread_create(&tid, nullptr, modInit, nullptr);
    pthread_detach(tid);
}
