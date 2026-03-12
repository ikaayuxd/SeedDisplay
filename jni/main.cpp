/**
 * SeedDisplay — 100% standalone, no libBedrockTools
 *
 * Own hooking  : inline ARM64 trampoline via mprotect + mmap
 * Own overlay  : raw OpenGL ES 2 (no ImGui) — draws seed text using
 *                a tiny bitmap font baked into the binary
 * Seed source  : StartGame packet hook (packet ID 0x0B)
 *
 * No external .so dependencies — just links against:
 *   liblog, libEGL, libGLESv2, libc, libdl
 */

#include <jni.h>
#include <android/log.h>
#include <EGL/egl.h>
#include <GLES2/gl2.h>
#include <pthread.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <link.h>

#define TAG  "SeedDisplay"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 1 — Tiny inline ARM64 hook engine (no Dobby / Substrate needed)
// ═════════════════════════════════════════════════════════════════════════════

// ARM64 absolute jump stub — 16 bytes:
//   LDR X17, #8
//   BR  X17
//   <8-byte target address>
static void writeJump(void* from, void* to) {
    // Make page writable
    uintptr_t page = (uintptr_t)from & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC);

    uint32_t* code = (uint32_t*)from;
    code[0] = 0x58000051; // LDR X17, #8
    code[1] = 0xD61F0220; // BR  X17
    uint64_t target = (uint64_t)to;
    memcpy(&code[2], &target, 8);

    // Flush instruction cache
    __builtin___clear_cache((char*)from, (char*)from + 16);
    mprotect((void*)page, 0x1000, PROT_READ | PROT_EXEC);
}

// Install a hook and save the original first 16 bytes + a trampoline
struct Hook {
    void*    target;
    uint8_t  saved[16];
    void*    trampoline; // mmap'd executable page with saved bytes + jump back
    bool     active;
};

static Hook* installHook(void* target, void* replacement) {
    if (!target || !replacement) return nullptr;

    Hook* h = (Hook*)malloc(sizeof(Hook));
    h->target = target;
    h->active = false;

    // Save original 16 bytes
    memcpy(h->saved, target, 16);

    // Build trampoline: [saved 16 bytes] + [jump back to target+16]
    void* tramp = mmap(nullptr, 0x1000,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) { free(h); return nullptr; }

    memcpy(tramp, h->saved, 16);
    // Jump back to target+16
    uint32_t* t = (uint32_t*)tramp + 4; // after 16 bytes
    t[0] = 0x58000051;
    t[1] = 0xD61F0220;
    uint64_t back = (uint64_t)target + 16;
    memcpy(&t[2], &back, 8);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 0x1000);

    h->trampoline = tramp;

    // Write the hook jump
    writeJump(target, replacement);
    h->active = true;

    LOGD("Hook installed: target=%p repl=%p tramp=%p", target, replacement, tramp);
    return h;
}

// Get the "original function" pointer from a hook (points to trampoline)
#define ORIG(h) ((h)->trampoline)

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 2 — Symbol resolver (walks /proc/self/maps + ELF dynsym)
// ═════════════════════════════════════════════════════════════════════════════

static uintptr_t getLibBase(const char* libname) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, libname) && strstr(line, "r--p")) {
            base = (uintptr_t)strtoull(line, nullptr, 16);
            break;
        }
    }
    // fallback: r-xp
    if (!base) {
        rewind(f);
        while (fgets(line, sizeof(line), f)) {
            if (strstr(line, libname) && strstr(line, "r-xp")) {
                base = (uintptr_t)strtoull(line, nullptr, 16);
                break;
            }
        }
    }
    fclose(f);
    return base;
}

static void* findSymbol(const char* libname, const char* symname) {
    uintptr_t base = getLibBase(libname);
    if (!base) {
        LOGE("findSymbol: no base for %s", libname);
        return nullptr;
    }

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0) {
        LOGE("findSymbol: bad ELF magic");
        return nullptr;
    }

    // Find dynamic segment
    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn*  dyn  = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr);
            break;
        }
    }
    if (!dyn) return nullptr;

    Elf64_Sym*  symtab = nullptr;
    const char* strtab = nullptr;
    size_t      symsz  = sizeof(Elf64_Sym);
    size_t      strsz  = 0;
    Elf64_Word* gnu_hash = nullptr;

    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
            case DT_SYMTAB:  symtab   = (Elf64_Sym*)(base + d->d_un.d_ptr); break;
            case DT_STRTAB:  strtab   = (const char*)(base + d->d_un.d_ptr); break;
            case DT_STRSZ:   strsz    = d->d_un.d_val; break;
            case DT_GNU_HASH:gnu_hash = (Elf64_Word*)(base + d->d_un.d_ptr); break;
        }
    }
    if (!symtab || !strtab) return nullptr;

    // Use GNU hash to find symbol count, then scan
    if (gnu_hash) {
        uint32_t nbuckets  = gnu_hash[0];
        uint32_t symoffset = gnu_hash[1];
        uint32_t bloom_sz  = gnu_hash[2];
        // skip bloom filter
        uint32_t* buckets = (uint32_t*)(gnu_hash + 4 + bloom_sz * 2);
        uint32_t* chain   = buckets + nbuckets;
        (void)chain;

        // Scan all symbols starting at symoffset
        // Estimate count from strtab
        size_t maxsyms = strsz / 4 + 100;
        for (size_t i = symoffset; i < symoffset + maxsyms; i++) {
            const char* name = strtab + symtab[i].st_name;
            if (name >= strtab + strsz) break;
            if (strcmp(name, symname) == 0 && symtab[i].st_value != 0) {
                void* addr = (void*)(base + symtab[i].st_value);
                LOGD("findSymbol(%s) = %p", symname, addr);
                return addr;
            }
        }
    }

    // Fallback: linear scan first 200000 entries
    for (size_t i = 0; i < 200000; i++) {
        if (symtab[i].st_name >= strsz) break;
        const char* name = strtab + symtab[i].st_name;
        if (strcmp(name, symname) == 0 && symtab[i].st_value != 0) {
            void* addr = (void*)(base + symtab[i].st_value);
            LOGD("findSymbol(%s) = %p (linear)", symname, addr);
            return addr;
        }
    }

    return nullptr;
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 3 — Own OpenGL ES 2 overlay (no ImGui)
//   Draws a rounded box + text using a simple pixel-font shader
// ═════════════════════════════════════════════════════════════════════════════

static GLuint g_prog   = 0;
static GLuint g_vbo    = 0;
static bool   g_glInit = false;

// Very small GLSL shaders
static const char* kVertSrc = R"glsl(
attribute vec2 aPos;
attribute vec2 aUV;
varying vec2 vUV;
uniform vec2 uScreen;
void main() {
    vec2 ndc = (aPos / uScreen) * 2.0 - 1.0;
    ndc.y = -ndc.y;
    gl_Position = vec4(ndc, 0.0, 1.0);
    vUV = aUV;
}
)glsl";

static const char* kFragSrc = R"glsl(
precision mediump float;
varying vec2 vUV;
uniform vec4 uColor;
uniform int  uMode;   // 0=solid rect, 1=text glyph
uniform sampler2D uTex;
void main() {
    if (uMode == 1) {
        float a = texture2D(uTex, vUV).r;
        gl_FragColor = vec4(uColor.rgb, uColor.a * a);
    } else {
        gl_FragColor = uColor;
    }
}
)glsl";

static GLuint compileShader(GLenum type, const char* src) {
    GLuint s = glCreateShader(type);
    glShaderSource(s, 1, &src, nullptr);
    glCompileShader(s);
    return s;
}

// ── Bitmap font (ASCII 32-126, 6x8 pixels each, 1bpp) ─────────────────────
// Encoded as 6 bytes per glyph (each byte = one column of 8 pixels)
// This is a minimal 6x8 font for the digits 0-9, A-Z, space, colon, minus, brackets
static const uint8_t kFont6x8[][6] = {
    // ' ' 32
    {0x00,0x00,0x00,0x00,0x00,0x00},
    // '!' 33
    {0x00,0x00,0x5F,0x00,0x00,0x00},
    // '"' 34
    {0x00,0x07,0x00,0x07,0x00,0x00},
    // '#' 35
    {0x14,0x7F,0x14,0x7F,0x14,0x00},
    // '$' 36
    {0x24,0x2A,0x7F,0x2A,0x12,0x00},
    // '%' 37
    {0x23,0x13,0x08,0x64,0x62,0x00},
    // '&' 38
    {0x36,0x49,0x55,0x22,0x50,0x00},
    // '\'' 39
    {0x00,0x05,0x03,0x00,0x00,0x00},
    // '(' 40
    {0x00,0x1C,0x22,0x41,0x00,0x00},
    // ')' 41
    {0x00,0x41,0x22,0x1C,0x00,0x00},
    // '*' 42
    {0x08,0x2A,0x1C,0x2A,0x08,0x00},
    // '+' 43
    {0x08,0x08,0x3E,0x08,0x08,0x00},
    // ',' 44
    {0x00,0x50,0x30,0x00,0x00,0x00},
    // '-' 45
    {0x08,0x08,0x08,0x08,0x08,0x00},
    // '.' 46
    {0x00,0x60,0x60,0x00,0x00,0x00},
    // '/' 47
    {0x20,0x10,0x08,0x04,0x02,0x00},
    // '0' 48
    {0x3E,0x51,0x49,0x45,0x3E,0x00},
    // '1' 49
    {0x00,0x42,0x7F,0x40,0x00,0x00},
    // '2' 50
    {0x42,0x61,0x51,0x49,0x46,0x00},
    // '3' 51
    {0x21,0x41,0x45,0x4B,0x31,0x00},
    // '4' 52
    {0x18,0x14,0x12,0x7F,0x10,0x00},
    // '5' 53
    {0x27,0x45,0x45,0x45,0x39,0x00},
    // '6' 54
    {0x3C,0x4A,0x49,0x49,0x30,0x00},
    // '7' 55
    {0x01,0x71,0x09,0x05,0x03,0x00},
    // '8' 56
    {0x36,0x49,0x49,0x49,0x36,0x00},
    // '9' 57
    {0x06,0x49,0x49,0x29,0x1E,0x00},
    // ':' 58
    {0x00,0x36,0x36,0x00,0x00,0x00},
    // ';' 59
    {0x00,0x56,0x36,0x00,0x00,0x00},
    // '<' 60
    {0x00,0x08,0x14,0x22,0x41,0x00},
    // '=' 61
    {0x14,0x14,0x14,0x14,0x14,0x00},
    // '>' 62
    {0x41,0x22,0x14,0x08,0x00,0x00},
    // '?' 63
    {0x02,0x01,0x51,0x09,0x06,0x00},
    // '@' 64
    {0x32,0x49,0x79,0x41,0x3E,0x00},
    // 'A' 65
    {0x7E,0x11,0x11,0x11,0x7E,0x00},
    // 'B' 66
    {0x7F,0x49,0x49,0x49,0x36,0x00},
    // 'C' 67
    {0x3E,0x41,0x41,0x41,0x22,0x00},
    // 'D' 68
    {0x7F,0x41,0x41,0x22,0x1C,0x00},
    // 'E' 69
    {0x7F,0x49,0x49,0x49,0x41,0x00},
    // 'F' 70
    {0x7F,0x09,0x09,0x09,0x01,0x00},
    // 'G' 71
    {0x3E,0x41,0x41,0x51,0x32,0x00},
    // 'H' 72
    {0x7F,0x08,0x08,0x08,0x7F,0x00},
    // 'I' 73
    {0x00,0x41,0x7F,0x41,0x00,0x00},
    // 'J' 74
    {0x20,0x40,0x41,0x3F,0x01,0x00},
    // 'K' 75
    {0x7F,0x08,0x14,0x22,0x41,0x00},
    // 'L' 76
    {0x7F,0x40,0x40,0x40,0x40,0x00},
    // 'M' 77
    {0x7F,0x02,0x04,0x02,0x7F,0x00},
    // 'N' 78
    {0x7F,0x04,0x08,0x10,0x7F,0x00},
    // 'O' 79
    {0x3E,0x41,0x41,0x41,0x3E,0x00},
    // 'P' 80
    {0x7F,0x09,0x09,0x09,0x06,0x00},
    // 'Q' 81
    {0x3E,0x41,0x51,0x21,0x5E,0x00},
    // 'R' 82
    {0x7F,0x09,0x19,0x29,0x46,0x00},
    // 'S' 83
    {0x46,0x49,0x49,0x49,0x31,0x00},
    // 'T' 84
    {0x01,0x01,0x7F,0x01,0x01,0x00},
    // 'U' 85
    {0x3F,0x40,0x40,0x40,0x3F,0x00},
    // 'V' 86
    {0x1F,0x20,0x40,0x20,0x1F,0x00},
    // 'W' 87
    {0x7F,0x20,0x18,0x20,0x7F,0x00},
    // 'X' 88
    {0x63,0x14,0x08,0x14,0x63,0x00},
    // 'Y' 89
    {0x03,0x04,0x78,0x04,0x03,0x00},
    // 'Z' 90
    {0x61,0x51,0x49,0x45,0x43,0x00},
    // '[' 91
    {0x00,0x00,0x7F,0x41,0x41,0x00},
    // '\\' 92
    {0x02,0x04,0x08,0x10,0x20,0x00},
    // ']' 93
    {0x41,0x41,0x7F,0x00,0x00,0x00},
    // '^' 94
    {0x04,0x02,0x01,0x02,0x04,0x00},
    // '_' 95
    {0x40,0x40,0x40,0x40,0x40,0x00},
};

static GLuint g_fontTex = 0;
static const int kGlyphW = 6, kGlyphH = 8;
static const int kGlyphCount = 64; // ASCII 32..95

static void buildFontTexture() {
    // Build a 1-channel texture: kGlyphCount glyphs side by side
    // Width = kGlyphCount * kGlyphW, Height = kGlyphH
    int tw = kGlyphCount * kGlyphW;
    int th = kGlyphH;
    uint8_t* pixels = (uint8_t*)calloc(tw * th, 1);

    for (int g = 0; g < kGlyphCount; g++) {
        for (int col = 0; col < kGlyphW; col++) {
            uint8_t colBits = kFont6x8[g][col];
            for (int row = 0; row < kGlyphH; row++) {
                int px = g * kGlyphW + col;
                int py = row;
                pixels[py * tw + px] = (colBits & (1 << row)) ? 255 : 0;
            }
        }
    }

    glGenTextures(1, &g_fontTex);
    glBindTexture(GL_TEXTURE_2D, g_fontTex);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_LUMINANCE, tw, th, 0,
                 GL_LUMINANCE, GL_UNSIGNED_BYTE, pixels);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
    free(pixels);
}

static void initGL() {
    GLuint vert = compileShader(GL_VERTEX_SHADER,   kVertSrc);
    GLuint frag = compileShader(GL_FRAGMENT_SHADER, kFragSrc);
    g_prog = glCreateProgram();
    glAttachShader(g_prog, vert);
    glAttachShader(g_prog, frag);
    glLinkProgram(g_prog);
    glDeleteShader(vert);
    glDeleteShader(frag);

    glGenBuffers(1, &g_vbo);
    buildFontTexture();
    g_glInit = true;
    LOGD("Own GL overlay initialised");
}

// Draw a filled rectangle (screen coords, top-left origin)
static void drawRect(float x, float y, float w, float h,
                     float r, float g, float b, float a,
                     float sw, float sh) {
    glUseProgram(g_prog);
    GLint uScreen = glGetUniformLocation(g_prog, "uScreen");
    GLint uColor  = glGetUniformLocation(g_prog, "uColor");
    GLint uMode   = glGetUniformLocation(g_prog, "uMode");
    GLint aPos    = glGetAttribLocation(g_prog,  "aPos");
    GLint aUV     = glGetAttribLocation(g_prog,  "aUV");

    glUniform2f(uScreen, sw, sh);
    glUniform4f(uColor, r, g, b, a);
    glUniform1i(uMode, 0);

    float verts[] = {
        x,   y,   0,0,
        x+w, y,   1,0,
        x,   y+h, 0,1,
        x+w, y+h, 1,1,
    };
    glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(verts), verts, GL_DYNAMIC_DRAW);
    glEnableVertexAttribArray(aPos);
    glEnableVertexAttribArray(aUV);
    glVertexAttribPointer(aPos, 2, GL_FLOAT, GL_FALSE, 4*4, (void*)0);
    glVertexAttribPointer(aUV,  2, GL_FLOAT, GL_FALSE, 4*4, (void*)8);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

// Draw a single glyph at scale
static void drawGlyph(char c, float x, float y, float scale,
                      float r, float g_, float b, float a,
                      float sw, float sh) {
    if (c < 32 || c > 95) c = '?';
    int idx = c - 32;

    float tw = (float)(kGlyphCount * kGlyphW);
    float th = (float)kGlyphH;
    float u0 = (idx * kGlyphW) / tw;
    float u1 = ((idx + 1) * kGlyphW) / tw;

    glUseProgram(g_prog);
    GLint uScreen = glGetUniformLocation(g_prog, "uScreen");
    GLint uColor  = glGetUniformLocation(g_prog, "uColor");
    GLint uMode   = glGetUniformLocation(g_prog, "uMode");
    GLint uTex    = glGetUniformLocation(g_prog, "uTex");
    GLint aPos    = glGetAttribLocation(g_prog,  "aPos");
    GLint aUV     = glGetAttribLocation(g_prog,  "aUV");

    glUniform2f(uScreen, sw, sh);
    glUniform4f(uColor, r, g_, b, a);
    glUniform1i(uMode, 1);
    glUniform1i(uTex, 0);

    float gw = kGlyphW * scale;
    float gh = kGlyphH * scale;

    float verts[] = {
        x,    y,    u0, 0,
        x+gw, y,    u1, 0,
        x,    y+gh, u0, 1,
        x+gw, y+gh, u1, 1,
    };
    glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, g_fontTex);
    glBindBuffer(GL_ARRAY_BUFFER, g_vbo);
    glBufferData(GL_ARRAY_BUFFER, sizeof(verts), verts, GL_DYNAMIC_DRAW);
    glEnableVertexAttribArray(aPos);
    glEnableVertexAttribArray(aUV);
    glVertexAttribPointer(aPos, 2, GL_FLOAT, GL_FALSE, 4*4, (void*)0);
    glVertexAttribPointer(aUV,  2, GL_FLOAT, GL_FALSE, 4*4, (void*)8);
    glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
}

// Draw a string
static void drawText(const char* str, float x, float y, float scale,
                     float r, float g, float b, float a,
                     float sw, float sh) {
    float cx = x;
    for (const char* p = str; *p; p++) {
        drawGlyph(*p, cx, y, scale, r, g, b, a, sw, sh);
        cx += kGlyphW * scale + scale;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 4 — Game state & overlay draw
// ═════════════════════════════════════════════════════════════════════════════

static int64_t g_seed        = 0;
static bool    g_hasSeed     = false;
static char    g_statusLine1[64] = "SEED DISPLAY";
static char    g_statusLine2[64] = "LOADING...";
static char    g_statusLine3[64] = "";
static float   g_sw = 1280, g_sh = 720;

static void renderOverlay() {
    if (!g_glInit) initGL();

    // Save GL state
    GLboolean blendWas; glGetBooleanv(GL_BLEND, &blendWas);
    GLint blendSrc, blendDst;
    glGetIntegerv(GL_BLEND_SRC_ALPHA, &blendSrc);
    glGetIntegerv(GL_BLEND_DST_ALPHA, &blendDst);

    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);

    float scale = 2.5f;
    float gw    = (kGlyphW + 1) * scale;
    float gh    = kGlyphH * scale;
    float pad   = 10.f;
    float lh    = gh + 4.f;

    // Figure out how many lines to draw
    int lines = g_statusLine3[0] ? 3 : (g_statusLine2[0] ? 2 : 1);
    float bw = 200.f;
    float bh = pad * 2 + lines * lh;
    float bx = 12.f, by = 12.f;

    // Background box (dark semi-transparent)
    drawRect(bx, by, bw, bh, 0.05f, 0.05f, 0.12f, 0.78f, g_sw, g_sh);
    // Top accent bar (blue)
    drawRect(bx, by, bw, 3.f, 0.2f, 0.6f, 1.0f, 1.0f, g_sw, g_sh);

    float tx = bx + pad;
    float ty = by + pad;

    // Line 1 — title/label (cyan)
    drawText(g_statusLine1, tx, ty, scale, 0.3f, 0.8f, 1.0f, 1.0f, g_sw, g_sh);
    ty += lh;

    // Line 2 — seed value or status (yellow if seed, white if status)
    if (g_hasSeed) {
        drawText(g_statusLine2, tx, ty, scale, 1.0f, 0.85f, 0.2f, 1.0f, g_sw, g_sh);
    } else {
        drawText(g_statusLine2, tx, ty, scale, 0.9f, 0.9f, 0.9f, 1.0f, g_sw, g_sh);
    }

    // Line 3 — extra info (green)
    if (g_statusLine3[0]) {
        ty += lh;
        drawText(g_statusLine3, tx, ty, scale, 0.4f, 1.0f, 0.5f, 1.0f, g_sw, g_sh);
    }

    // Restore blend
    if (!blendWas) glDisable(GL_BLEND);
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 5 — Packet parsing (StartGame = 0x0B)
// ═════════════════════════════════════════════════════════════════════════════

static uint64_t readVarU(const uint8_t* b, size_t l, size_t& p) {
    uint64_t r = 0; int s = 0;
    while (p < l) { uint8_t x = b[p++]; r |= (uint64_t)(x&0x7F)<<s; if(!(x&0x80))break; s+=7; }
    return r;
}
static int64_t readVarZ(const uint8_t* b, size_t l, size_t& p) {
    uint64_t v = readVarU(b,l,p); return (int64_t)((v>>1)^-(int64_t)(v&1));
}
static void skipStr(const uint8_t* b, size_t l, size_t& p) {
    uint64_t n = readVarU(b,l,p); p += n; if(p>l) p=l;
}

static bool tryParseStartGame(const uint8_t* data, size_t len) {
    if (len < 20) return false;
    size_t p = 0;

    readVarZ(data, len, p);  // entityUniqueId
    readVarU(data, len, p);  // entityRuntimeId
    readVarU(data, len, p);  // playerGamemode
    if (p + 20 > len) return false;
    p += 12; // playerPosition (3 floats)
    p += 8;  // rotation (2 floats)

    // Seed: LE int64
    if (p + 8 > len) return false;
    int64_t seed = 0;
    memcpy(&seed, data + p, 8);
    p += 8;

    LOGD("StartGame -> seed=%lld", (long long)seed);
    g_seed = seed;
    g_hasSeed = true;

    snprintf(g_statusLine1, sizeof(g_statusLine1), "SEED DISPLAY");
    snprintf(g_statusLine2, sizeof(g_statusLine2), "%lld", (long long)seed);
    snprintf(g_statusLine3, sizeof(g_statusLine3), "PACKET OK");
    return true;
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 6 — Hooks
// ═════════════════════════════════════════════════════════════════════════════

// ── eglSwapBuffers ────────────────────────────────────────────────────────────
typedef EGLBoolean (*FnSwap)(EGLDisplay, EGLSurface);
static Hook*  g_swapHook  = nullptr;

static EGLBoolean my_eglSwapBuffers(EGLDisplay dpy, EGLSurface surf) {
    // Get surface size
    EGLint w = 0, h = 0;
    eglQuerySurface(dpy, surf, EGL_WIDTH,  &w);
    eglQuerySurface(dpy, surf, EGL_HEIGHT, &h);
    if (w > 0) g_sw = (float)w;
    if (h > 0) g_sh = (float)h;

    renderOverlay();

    FnSwap orig = (FnSwap)ORIG(g_swapHook);
    return orig(dpy, surf);
}

// ── StartGamePacket handler ───────────────────────────────────────────────────
typedef void (*FnHandlePkt)(void*, void*, void*);
static Hook* g_pktHook = nullptr;
static int   g_hookedSym = -1;

static void my_handleStartGame(void* a, void* b, void* pkt) {
    // Try reading seed from packet object at various offsets
    if (!g_hasSeed && pkt) {
        // Dump first 160 bytes of packet object to find seed
        static bool dumped = false;
        if (!dumped) {
            dumped = true;
            LOGD("StartGamePacket dump:");
            for (int off = 0; off < 160; off += 8) {
                int64_t v = 0;
                memcpy(&v, (uint8_t*)pkt + off, 8);
                LOGD("  +0x%02X : %lld (0x%llX)", off, (long long)v, (unsigned long long)v);
            }
        }

        // Try common seed offsets
        const int offs[] = {0x68,0x70,0x78,0x80,0x88,0x90,0x98,0xA0,0xA8,0xB0,-1};
        for (int i = 0; offs[i] != -1; i++) {
            int64_t v = 0;
            memcpy(&v, (uint8_t*)pkt + offs[i], 8);
            // A plausible seed: non-zero, fits in signed 32 bits or is a known large value
            if (v != 0 && v != -1 && v > -2000000000LL && v < 2000000000LL) {
                g_seed    = v;
                g_hasSeed = true;
                snprintf(g_statusLine1, sizeof(g_statusLine1), "SEED DISPLAY");
                snprintf(g_statusLine2, sizeof(g_statusLine2), "%lld", (long long)v);
                snprintf(g_statusLine3, sizeof(g_statusLine3), "HOOK SYM %d", g_hookedSym);
                LOGD("Seed from pkt offset 0x%X = %lld", offs[i], (long long)v);
                break;
            }
        }
    }

    FnHandlePkt orig = (FnHandlePkt)ORIG(g_pktHook);
    orig(a, b, pkt);
}

// ── StartGamePacket::read ─────────────────────────────────────────────────────
typedef void* (*FnPktRead)(void*, void*);
static Hook* g_readHook = nullptr;

// ReadOnlyBinaryStream: buffer at +0x8, size at +0x10
static void* my_pktRead(void* pkt, void* stream) {
    FnPktRead orig = (FnPktRead)ORIG(g_readHook);
    void* ret = orig(pkt, stream);

    if (!g_hasSeed && stream) {
        const uint8_t* buf  = nullptr;
        size_t         blen = 0;
        memcpy(&buf,  (uint8_t*)stream + 0x08, sizeof(buf));
        memcpy(&blen, (uint8_t*)stream + 0x10, sizeof(blen));
        if (buf && blen > 10) {
            LOGD("StartGamePacket::read buf=%p len=%zu", buf, blen);
            tryParseStartGame(buf, blen);
            if (g_hasSeed)
                snprintf(g_statusLine3, sizeof(g_statusLine3), "READ HOOK");
        }
    }
    return ret;
}

// ═════════════════════════════════════════════════════════════════════════════
// SECTION 7 — Init
// ═════════════════════════════════════════════════════════════════════════════

static void* modInit(void*) {
    sleep(3);
    LOGD("=== SeedDisplay standalone init ===");

    snprintf(g_statusLine2, sizeof(g_statusLine2), "HOOKING...");

    // ── Hook eglSwapBuffers ───────────────────────────────────────────────────
    // Get address from libEGL.so directly
    void* eglLib = dlopen("libEGL.so", RTLD_NOW | RTLD_NOLOAD);
    void* eglSwapAddr = eglLib ? dlsym(eglLib, "eglSwapBuffers") : nullptr;
    if (!eglSwapAddr) eglSwapAddr = (void*)eglSwapBuffers;

    g_swapHook = installHook(eglSwapAddr, (void*)my_eglSwapBuffers);
    if (g_swapHook) {
        LOGD("eglSwapBuffers hooked at %p", eglSwapAddr);
        snprintf(g_statusLine2, sizeof(g_statusLine2), "OVERLAY OK");
    } else {
        LOGE("eglSwapBuffers hook FAILED");
        snprintf(g_statusLine2, sizeof(g_statusLine2), "SWAP HOOK FAIL");
    }

    // ── Hook StartGame packet symbols ─────────────────────────────────────────
    const char* kHandleSyms[] = {
        "_ZN14NetworkHandler6handleERKN15NetworkIdentifierERK15StartGamePacket",
        "_ZN21ServerNetworkHandler6handleERKN15NetworkIdentifierERK15StartGamePacket",
        "_ZN14NetworkHandler22_handleStartGamePacketERKN15NetworkIdentifierERK15StartGamePacket",
        nullptr
    };

    bool hooked = false;
    for (int i = 0; kHandleSyms[i] && !hooked; i++) {
        void* addr = findSymbol("libminecraftpe.so", kHandleSyms[i]);
        LOGD("Handle[%d] %s -> %p", i, kHandleSyms[i], addr);
        if (addr) {
            g_pktHook  = installHook(addr, (void*)my_handleStartGame);
            g_hookedSym = i;
            hooked      = true;
            snprintf(g_statusLine3, sizeof(g_statusLine3), "SYM %d HOOKED", i);
        }
    }

    // Fallback: StartGamePacket::read
    if (!hooked) {
        const char* kReadSyms[] = {
            "_ZN15StartGamePacket4readER20ReadOnlyBinaryStream",
            "_ZN15StartGamePacket11_readPacketER20ReadOnlyBinaryStream",
            nullptr
        };
        for (int i = 0; kReadSyms[i] && !hooked; i++) {
            void* addr = findSymbol("libminecraftpe.so", kReadSyms[i]);
            LOGD("Read[%d] %s -> %p", i, kReadSyms[i], addr);
            if (addr) {
                g_readHook = installHook(addr, (void*)my_pktRead);
                hooked     = true;
                snprintf(g_statusLine3, sizeof(g_statusLine3), "READ %d HOOKED", i);
            }
        }
    }

    if (!hooked) {
        LOGE("No StartGame symbol found");
        snprintf(g_statusLine3, sizeof(g_statusLine3), "NO SYM FOUND");
    }

    snprintf(g_statusLine2, sizeof(g_statusLine2),
             hooked ? "JOIN WORLD..." : "SYM NOT FOUND");

    LOGD("=== init done ===");
    return nullptr;
}

__attribute__((constructor))
static void onLoad() {
    LOGD("SeedDisplay standalone loaded");
    snprintf(g_statusLine1, sizeof(g_statusLine1), "SEED DISPLAY");
    snprintf(g_statusLine2, sizeof(g_statusLine2), "STARTING...");
    pthread_t tid;
    pthread_create(&tid, nullptr, modInit, nullptr);
    pthread_detach(tid);
}
