/**
 * SeedDisplay — Symbol Scanner
 * Scans libminecraftpe.so for seed symbols and shows them ON SCREEN
 * No logcat needed — everything displayed in game overlay
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
#include <link.h>

#define TAG "SeedDisplay"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ═══════════════════════════════════════════════════════════════
// ARM64 Hook engine
// ═══════════════════════════════════════════════════════════════
struct Hook { void* target; uint8_t saved[16]; void* tramp; };

static Hook* installHook(void* target, void* replacement) {
    if (!target || !replacement) return nullptr;
    Hook* h = (Hook*)malloc(sizeof(Hook));
    h->target = target;
    memcpy(h->saved, target, 16);

    void* tramp = mmap(nullptr, 0x1000,
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) { free(h); return nullptr; }

    memcpy(tramp, h->saved, 16);
    uint32_t* t = (uint32_t*)tramp + 4;
    t[0] = 0x58000051; t[1] = 0xD61F0220;
    uint64_t back = (uint64_t)target + 16;
    memcpy(&t[2], &back, 8);
    __builtin___clear_cache((char*)tramp, (char*)tramp + 0x1000);
    h->tramp = tramp;

    uintptr_t page = (uintptr_t)target & ~0xFFFULL;
    mprotect((void*)page, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC);
    uint32_t* code = (uint32_t*)target;
    code[0] = 0x58000051; code[1] = 0xD61F0220;
    uint64_t dst = (uint64_t)replacement;
    memcpy(&code[2], &dst, 8);
    __builtin___clear_cache((char*)target, (char*)target + 16);
    mprotect((void*)page, 0x1000, PROT_READ|PROT_EXEC);
    return h;
}
#define ORIG(h) ((h)->tramp)

// ═══════════════════════════════════════════════════════════════
// ELF symbol scanner
// ═══════════════════════════════════════════════════════════════
static uintptr_t getLibBase(const char* lib) {
    FILE* f = fopen("/proc/self/maps", "r");
    if (!f) return 0;
    char line[512]; uintptr_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, lib) && (strstr(line, "r--p") || strstr(line, "r-xp"))) {
            base = (uintptr_t)strtoull(line, nullptr, 16); break;
        }
    }
    fclose(f); return base;
}

// Scan for symbols containing a keyword, store results in out[]
static int scanSymbols(const char* libname, const char* keyword,
                        char out[][128], int maxResults) {
    uintptr_t base = getLibBase(libname);
    if (!base) return 0;

    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0) return 0;

    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn*  dyn  = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr); break;
        }
    }
    if (!dyn) return 0;

    Elf64_Sym* symtab = nullptr;
    const char* strtab = nullptr;
    size_t strsz = 0;

    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if      (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB) strtab = (const char*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRSZ)  strsz  = d->d_un.d_val;
    }
    if (!symtab || !strtab || !strsz) return 0;

    int found = 0;
    for (size_t i = 1; i < 800000 && found < maxResults; i++) {
        if ((uintptr_t)&symtab[i] > base + 0x4000000) break;
        if (symtab[i].st_name >= strsz) continue;
        const char* name = strtab + symtab[i].st_name;
        if (symtab[i].st_value == 0) continue;
        // case-insensitive keyword search
        char lname[256]; size_t nl = strlen(name);
        if (nl > 255) continue;
        for (size_t j = 0; j <= nl; j++) lname[j] = (name[j]>='A'&&name[j]<='Z') ? name[j]+32 : name[j];
        if (strstr(lname, keyword)) {
            strncpy(out[found], name, 127);
            out[found][127] = 0;
            found++;
        }
    }
    return found;
}

static void* findSymbol(const char* libname, const char* symname) {
    uintptr_t base = getLibBase(libname);
    if (!base) return nullptr;
    Elf64_Ehdr* ehdr = (Elf64_Ehdr*)base;
    if (memcmp(ehdr->e_ident, "\x7f""ELF", 4) != 0) return nullptr;
    Elf64_Phdr* phdr = (Elf64_Phdr*)(base + ehdr->e_phoff);
    Elf64_Dyn* dyn = nullptr;
    for (int i = 0; i < ehdr->e_phnum; i++)
        if (phdr[i].p_type == PT_DYNAMIC) { dyn = (Elf64_Dyn*)(base + phdr[i].p_vaddr); break; }
    if (!dyn) return nullptr;
    Elf64_Sym* symtab = nullptr; const char* strtab = nullptr; size_t strsz = 0;
    for (Elf64_Dyn* d = dyn; d->d_tag != DT_NULL; d++) {
        if      (d->d_tag == DT_SYMTAB) symtab = (Elf64_Sym*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRTAB) strtab = (const char*)(base + d->d_un.d_ptr);
        else if (d->d_tag == DT_STRSZ)  strsz  = d->d_un.d_val;
    }
    if (!symtab || !strtab) return nullptr;
    for (size_t i = 1; i < 800000; i++) {
        if ((uintptr_t)&symtab[i] > base + 0x4000000) break;
        if (symtab[i].st_name >= strsz || symtab[i].st_value == 0) continue;
        if (strcmp(strtab + symtab[i].st_name, symname) == 0)
            return (void*)(base + symtab[i].st_value);
    }
    return nullptr;
}

// ═══════════════════════════════════════════════════════════════
// Own OpenGL ES2 text overlay (6x8 bitmap font)
// ═══════════════════════════════════════════════════════════════
static const uint8_t kFont[][6] = {
    {0x00,0x00,0x00,0x00,0x00,0x00}, // ' '
    {0x00,0x00,0x5F,0x00,0x00,0x00}, // !
    {0x00,0x07,0x00,0x07,0x00,0x00}, // "
    {0x14,0x7F,0x14,0x7F,0x14,0x00}, // #
    {0x24,0x2A,0x7F,0x2A,0x12,0x00}, // $
    {0x23,0x13,0x08,0x64,0x62,0x00}, // %
    {0x36,0x49,0x55,0x22,0x50,0x00}, // &
    {0x00,0x05,0x03,0x00,0x00,0x00}, // '
    {0x00,0x1C,0x22,0x41,0x00,0x00}, // (
    {0x00,0x41,0x22,0x1C,0x00,0x00}, // )
    {0x08,0x2A,0x1C,0x2A,0x08,0x00}, // *
    {0x08,0x08,0x3E,0x08,0x08,0x00}, // +
    {0x00,0x50,0x30,0x00,0x00,0x00}, // ,
    {0x08,0x08,0x08,0x08,0x08,0x00}, // -
    {0x00,0x60,0x60,0x00,0x00,0x00}, // .
    {0x20,0x10,0x08,0x04,0x02,0x00}, // /
    {0x3E,0x51,0x49,0x45,0x3E,0x00}, // 0
    {0x00,0x42,0x7F,0x40,0x00,0x00}, // 1
    {0x42,0x61,0x51,0x49,0x46,0x00}, // 2
    {0x21,0x41,0x45,0x4B,0x31,0x00}, // 3
    {0x18,0x14,0x12,0x7F,0x10,0x00}, // 4
    {0x27,0x45,0x45,0x45,0x39,0x00}, // 5
    {0x3C,0x4A,0x49,0x49,0x30,0x00}, // 6
    {0x01,0x71,0x09,0x05,0x03,0x00}, // 7
    {0x36,0x49,0x49,0x49,0x36,0x00}, // 8
    {0x06,0x49,0x49,0x29,0x1E,0x00}, // 9
    {0x00,0x36,0x36,0x00,0x00,0x00}, // :
    {0x00,0x56,0x36,0x00,0x00,0x00}, // ;
    {0x00,0x08,0x14,0x22,0x41,0x00}, // <
    {0x14,0x14,0x14,0x14,0x14,0x00}, // =
    {0x41,0x22,0x14,0x08,0x00,0x00}, // >
    {0x02,0x01,0x51,0x09,0x06,0x00}, // ?
    {0x32,0x49,0x79,0x41,0x3E,0x00}, // @
    {0x7E,0x11,0x11,0x11,0x7E,0x00}, // A
    {0x7F,0x49,0x49,0x49,0x36,0x00}, // B
    {0x3E,0x41,0x41,0x41,0x22,0x00}, // C
    {0x7F,0x41,0x41,0x22,0x1C,0x00}, // D
    {0x7F,0x49,0x49,0x49,0x41,0x00}, // E
    {0x7F,0x09,0x09,0x09,0x01,0x00}, // F
    {0x3E,0x41,0x41,0x51,0x32,0x00}, // G
    {0x7F,0x08,0x08,0x08,0x7F,0x00}, // H
    {0x00,0x41,0x7F,0x41,0x00,0x00}, // I
    {0x20,0x40,0x41,0x3F,0x01,0x00}, // J
    {0x7F,0x08,0x14,0x22,0x41,0x00}, // K
    {0x7F,0x40,0x40,0x40,0x40,0x00}, // L
    {0x7F,0x02,0x04,0x02,0x7F,0x00}, // M
    {0x7F,0x04,0x08,0x10,0x7F,0x00}, // N
    {0x3E,0x41,0x41,0x41,0x3E,0x00}, // O
    {0x7F,0x09,0x09,0x09,0x06,0x00}, // P
    {0x3E,0x41,0x51,0x21,0x5E,0x00}, // Q
    {0x7F,0x09,0x19,0x29,0x46,0x00}, // R
    {0x46,0x49,0x49,0x49,0x31,0x00}, // S
    {0x01,0x01,0x7F,0x01,0x01,0x00}, // T
    {0x3F,0x40,0x40,0x40,0x3F,0x00}, // U
    {0x1F,0x20,0x40,0x20,0x1F,0x00}, // V
    {0x7F,0x20,0x18,0x20,0x7F,0x00}, // W
    {0x63,0x14,0x08,0x14,0x63,0x00}, // X
    {0x03,0x04,0x78,0x04,0x03,0x00}, // Y
    {0x61,0x51,0x49,0x45,0x43,0x00}, // Z
    {0x00,0x00,0x7F,0x41,0x41,0x00}, // [
    {0x02,0x04,0x08,0x10,0x20,0x00}, // backslash
    {0x41,0x41,0x7F,0x00,0x00,0x00}, // ]
    {0x04,0x02,0x01,0x02,0x04,0x00}, // ^
    {0x40,0x40,0x40,0x40,0x40,0x00}, // _
};

static GLuint g_prog=0, g_vbo=0, g_fontTex=0;
static bool   g_glReady = false;

static const char* kVert = R"(
attribute vec2 aPos; attribute vec2 aUV; varying vec2 vUV;
uniform vec2 uSz;
void main(){vec2 n=(aPos/uSz)*2.0-1.0;n.y=-n.y;gl_Position=vec4(n,0,1);vUV=aUV;}
)";
static const char* kFrag = R"(
precision mediump float;
varying vec2 vUV; uniform vec4 uCol; uniform int uMode; uniform sampler2D uTex;
void main(){if(uMode==1){float a=texture2D(uTex,vUV).r;gl_FragColor=vec4(uCol.rgb,uCol.a*a);}else{gl_FragColor=uCol;}}
)";

static GLuint mkShader(GLenum t, const char* s){
    GLuint sh=glCreateShader(t); glShaderSource(sh,1,&s,nullptr);
    glCompileShader(sh); return sh;
}

static void glInit() {
    GLuint v=mkShader(GL_VERTEX_SHADER,kVert), f=mkShader(GL_FRAGMENT_SHADER,kFrag);
    g_prog=glCreateProgram(); glAttachShader(g_prog,v); glAttachShader(g_prog,f);
    glLinkProgram(g_prog); glDeleteShader(v); glDeleteShader(f);
    glGenBuffers(1,&g_vbo);

    // Font texture
    const int GW=6,GH=8,GN=64,TW=GN*GW;
    uint8_t* px=(uint8_t*)calloc(TW*GH,1);
    for(int g=0;g<GN;g++) for(int c=0;c<GW;c++) for(int r=0;r<GH;r++)
        if(kFont[g][c]&(1<<r)) px[r*TW+g*GW+c]=255;
    glGenTextures(1,&g_fontTex);
    glBindTexture(GL_TEXTURE_2D,g_fontTex);
    glTexImage2D(GL_TEXTURE_2D,0,GL_LUMINANCE,TW,GH,0,GL_LUMINANCE,GL_UNSIGNED_BYTE,px);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MIN_FILTER,GL_NEAREST);
    glTexParameteri(GL_TEXTURE_2D,GL_TEXTURE_MAG_FILTER,GL_NEAREST);
    free(px);
    g_glReady=true;
}

static float g_sw=1280,g_sh=720;

static void rect(float x,float y,float w,float h,float r,float g,float b,float a){
    glUseProgram(g_prog);
    glUniform2f(glGetUniformLocation(g_prog,"uSz"),g_sw,g_sh);
    glUniform4f(glGetUniformLocation(g_prog,"uCol"),r,g,b,a);
    glUniform1i(glGetUniformLocation(g_prog,"uMode"),0);
    float v[]={x,y,0,0, x+w,y,1,0, x,y+h,0,1, x+w,y+h,1,1};
    glBindBuffer(GL_ARRAY_BUFFER,g_vbo);
    glBufferData(GL_ARRAY_BUFFER,sizeof(v),v,GL_DYNAMIC_DRAW);
    GLint ap=glGetAttribLocation(g_prog,"aPos"),au=glGetAttribLocation(g_prog,"aUV");
    glEnableVertexAttribArray(ap); glEnableVertexAttribArray(au);
    glVertexAttribPointer(ap,2,GL_FLOAT,GL_FALSE,16,(void*)0);
    glVertexAttribPointer(au,2,GL_FLOAT,GL_FALSE,16,(void*)8);
    glDrawArrays(GL_TRIANGLE_STRIP,0,4);
}

static void glyph(char c,float x,float y,float sc,float r,float g,float b,float a){
    if(c<32||c>95) c='?';
    int idx=c-32;
    const int GW=6,GH=8,GN=64;
    float tw=GN*GW, u0=idx*GW/tw, u1=(idx+1)*GW/tw;
    glUseProgram(g_prog);
    glUniform2f(glGetUniformLocation(g_prog,"uSz"),g_sw,g_sh);
    glUniform4f(glGetUniformLocation(g_prog,"uCol"),r,g,b,a);
    glUniform1i(glGetUniformLocation(g_prog,"uMode"),1);
    glUniform1i(glGetUniformLocation(g_prog,"uTex"),0);
    float fw=GW*sc,fh=GH*sc;
    float v[]={x,y,u0,0, x+fw,y,u1,0, x,y+fh,u0,1, x+fw,y+fh,u1,1};
    glActiveTexture(GL_TEXTURE0); glBindTexture(GL_TEXTURE_2D,g_fontTex);
    glBindBuffer(GL_ARRAY_BUFFER,g_vbo);
    glBufferData(GL_ARRAY_BUFFER,sizeof(v),v,GL_DYNAMIC_DRAW);
    GLint ap=glGetAttribLocation(g_prog,"aPos"),au=glGetAttribLocation(g_prog,"aUV");
    glEnableVertexAttribArray(ap); glEnableVertexAttribArray(au);
    glVertexAttribPointer(ap,2,GL_FLOAT,GL_FALSE,16,(void*)0);
    glVertexAttribPointer(au,2,GL_FLOAT,GL_FALSE,16,(void*)8);
    glDrawArrays(GL_TRIANGLE_STRIP,0,4);
}

static float text(const char* s,float x,float y,float sc,float r,float g,float b,float a){
    // convert to upper for our font range
    char buf[128]; int i=0;
    for(;s[i]&&i<127;i++){ char c=s[i]; if(c>='a'&&c<='z') c-=32; buf[i]=c; }
    buf[i]=0;
    float cx=x;
    for(int j=0;buf[j];j++){ glyph(buf[j],cx,y,sc,r,g,b,a); cx+=(6+1)*sc; }
    return cx;
}

// ═══════════════════════════════════════════════════════════════
// App state
// ═══════════════════════════════════════════════════════════════
#define MAX_LINES 20
static char  g_lines[MAX_LINES][64];
static int   g_lineCount = 0;
static bool  g_hasSeed   = false;
static int64_t g_seed    = 0;

static pthread_mutex_t g_mtx = PTHREAD_MUTEX_INITIALIZER;

static void addLine(const char* fmt, ...) {
    pthread_mutex_lock(&g_mtx);
    if (g_lineCount < MAX_LINES) {
        va_list ap; va_start(ap, fmt);
        vsnprintf(g_lines[g_lineCount++], 63, fmt, ap);
        va_end(ap);
    }
    pthread_mutex_unlock(&g_mtx);
}

// ═══════════════════════════════════════════════════════════════
// eglSwapBuffers hook — draws overlay
// ═══════════════════════════════════════════════════════════════
typedef EGLBoolean (*FnSwap)(EGLDisplay,EGLSurface);
static Hook* g_swapHook = nullptr;

static EGLBoolean my_swap(EGLDisplay dpy, EGLSurface surf) {
    EGLint w=0,h=0;
    eglQuerySurface(dpy,surf,EGL_WIDTH,&w);
    eglQuerySurface(dpy,surf,EGL_HEIGHT,&h);
    if(w>0){g_sw=(float)w;g_sh=(float)h;}

    if(!g_glReady) glInit();

    GLboolean blendOn; glGetBooleanv(GL_BLEND,&blendOn);
    glEnable(GL_BLEND);
    glBlendFunc(GL_SRC_ALPHA,GL_ONE_MINUS_SRC_ALPHA);

    float sc=2.0f, lh=8*sc+3, pad=8;
    pthread_mutex_lock(&g_mtx);
    int n = g_lineCount;
    char lines[MAX_LINES][64];
    memcpy(lines, g_lines, sizeof(lines));
    pthread_mutex_unlock(&g_mtx);

    // box height: title + seed (if any) + scan lines
    float bh = pad*2 + lh*(1 + (g_hasSeed?1:0) + n);
    float bw = 310;

    // background
    rect(10,10,bw,bh, 0.04f,0.04f,0.10f,0.82f);
    // top bar
    rect(10,10,bw,3,   0.2f,0.6f,1.0f,1.0f);

    float tx=18, ty=14;
    // Title
    text("SEED DISPLAY",tx,ty,sc, 0.3f,0.8f,1.0f,1.0f); ty+=lh;

    // Seed value if found
    if(g_hasSeed){
        char buf[32]; snprintf(buf,sizeof(buf),"%lld",(long long)g_seed);
        text("SEED:",tx,ty,sc, 0.7f,0.7f,0.7f,1.0f);
        text(buf, tx+50,ty,sc, 1.0f,0.9f,0.2f,1.0f);
        ty+=lh;
    }

    // Scan lines
    for(int i=0;i<n;i++){
        // colour: green for found symbols, yellow for status, white for others
        float r=0.8f,g_=0.8f,b_=0.8f;
        if(strstr(lines[i],"FOUND"))  { r=0.2f;g_=1.0f;b_=0.4f; }
        if(strstr(lines[i],"SEED"))   { r=1.0f;g_=0.9f;b_=0.2f; }
        if(strstr(lines[i],"FAIL")||strstr(lines[i],"NO "))
                                       { r=1.0f;g_=0.3f;b_=0.3f; }
        text(lines[i],tx,ty,sc,r,g_,b_,1.0f);
        ty+=lh;
    }

    if(!blendOn) glDisable(GL_BLEND);

    return ((FnSwap)ORIG(g_swapHook))(dpy,surf);
}

// ═══════════════════════════════════════════════════════════════
// StartGame packet hook (try multiple symbols)
// ═══════════════════════════════════════════════════════════════
typedef void (*FnHandle)(void*,void*,void*);
static Hook* g_pktHook = nullptr;

static void my_handleStartGame(void* a, void* b, void* pkt) {
    if (!g_hasSeed && pkt) {
        // Try reading seed from common offsets
        const int offs[] = {0x50,0x58,0x60,0x68,0x70,0x78,0x80,0x88,0x90,0x98,0xA0,0xA8,0xB0,-1};
        for (int i = 0; offs[i]!=-1; i++) {
            int64_t v=0; memcpy(&v,(uint8_t*)pkt+offs[i],8);
            if(v!=0&&v!=-1&&v>-2100000000LL&&v<2100000000LL&&v!=0x100000000LL){
                g_seed=v; g_hasSeed=true;
                addLine("SEED: %lld",(long long)v);
                addLine("OFF 0x%X",(unsigned)offs[i]);
                break;
            }
        }
        if(!g_hasSeed) addLine("PKT: NO SEED FOUND");
    }
    ((FnHandle)ORIG(g_pktHook))(a,b,pkt);
}

// ═══════════════════════════════════════════════════════════════
// Init thread — scan + hook
// ═══════════════════════════════════════════════════════════════
static void* modInit(void*) {
    sleep(3);
    addLine("SCANNING...");

    // 1. Hook eglSwapBuffers
    void* eglAddr = (void*)eglSwapBuffers;
    g_swapHook = installHook(eglAddr, (void*)my_swap);
    addLine(g_swapHook ? "SWAP HOOK OK" : "SWAP HOOK FAIL");

    // 2. Scan for seed-related symbols in libminecraftpe.so
    addLine("LOOKING 4 SYMS");
    char found[16][128];
    int n = scanSymbols("libminecraftpe.so", "seed", found, 16);
    addLine("SEED SYMS: %d", n);

    for(int i=0;i<n;i++){
        // Show shortened symbol (last 20 chars so it fits on screen)
        const char* s = found[i];
        int sl = strlen(s);
        const char* show = sl>20 ? s+sl-20 : s;
        addLine("F:%s", show);
        LOGD("SEED SYM: %s", s);
    }

    // 3. Try to hook the best candidate
    const char* kTry[] = {
        "_ZN14NetworkHandler6handleERKN15NetworkIdentifierERK15StartGamePacket",
        "_ZN21ServerNetworkHandler6handleERKN15NetworkIdentifierERK15StartGamePacket",
        "_ZN14NetworkHandler22_handleStartGamePacketERKN15NetworkIdentifierERK15StartGamePacket",
        "_ZN15StartGamePacket4readER20ReadOnlyBinaryStream",
        // Try any found seed symbol too
        nullptr
    };

    bool hooked = false;
    for(int i=0; kTry[i] && !hooked; i++){
        void* addr = findSymbol("libminecraftpe.so", kTry[i]);
        if(addr){
            g_pktHook = installHook(addr,(void*)my_handleStartGame);
            if(g_pktHook){ addLine("HOOKED SYM %d",i); hooked=true; }
        }
    }

    // Also try hooking the first found seed symbol directly
    if(!hooked && n>0){
        void* addr = findSymbol("libminecraftpe.so", found[0]);
        if(addr){
            g_pktHook = installHook(addr,(void*)my_handleStartGame);
            if(g_pktHook){ addLine("HOOKED FOUND[0]"); hooked=true; }
        }
    }

    if(!hooked) addLine("NO HOOK - SEE F:");
    else        addLine("JOIN WORLD NOW");

    return nullptr;
}

__attribute__((constructor))
static void onLoad(){
    LOGD("SeedDisplay scanner loaded");
    addLine("SEED SCANNER V2");
    pthread_t tid;
    pthread_create(&tid,nullptr,modInit,nullptr);
    pthread_detach(tid);
}
