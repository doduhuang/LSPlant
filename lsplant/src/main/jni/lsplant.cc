module;

#include "lsplant.hpp"

#include <android/api-level.h>
#include <bits/sysconf.h>
#include <jni.h>
#include <sched.h>  /* M4b-Polish I3 codex T1 round 4: sched_yield for transient EBUSY retry */
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <bit>
#include <cstdlib>
#include <mutex>
#include <condition_variable>
#include <pthread.h>
#include <string_view>
#include <tuple>

#include "logging.hpp"

/* M4b-Polish T3 I2: 共享 slot sentinel 常量。优先 quoted-include 解析 jni/ 同目录的
 * vendored 副本（让 lsplant fork standalone build 工作）；shadowhook build 因
 * bridge/CMakeLists.txt 对 lsplant_static 暴露 SH_ROOT/include，但 quoted-include 也
 * 优先 jni/ 副本（与 canonical 等价 → 单源对外行为一致）。改 ABI 时必须同步更新两份。 */
#include "shadowhook_lsplant_abi.h"

/* ============================================================================
 * shadowhook M4b PTE/UXN integration (M4b.3 fork modification)
 * ============================================================================
 * 声明放在 global module fragment（module; … module lsplant; 之间），与其它 #include
 * 同段——这里的 entity 既属于 global 模块，又被 lsplant 模块 import 后的 DoHook 在
 * extern "C++"/extern "C" 上下文里能链接到。
 *
 * 在 -DLSPLANT_SKIP_ENTRY_POINT_PATCH 构建（M4b 主路径，bridge/CMakeLists.txt 注入）下，
 * DoHook 不再 `target->SetEntryPoint(entrypoint)`（M4a 原模式），改调本 wrapper:
 *   - target_oat_va = target->GetEntryPoint()   // 原 .oat 段地址，未被覆盖
 *   - shadowhook_pte_install_for_lsplant(.oat, entrypoint)
 *     ↓
 *   - bridge/lsplant_glue.cpp 内 C-linkage 转 shadowhook::stealth_inline_hooker
 *     ↓
 *   - sh_pte_hook_install(target_oat_va, hook_callback_va=entrypoint, pid=getpid(), &slot)
 *     ↓
 *   - KPM: PTE.UXN=1 → CPU 取指 trap → do_mem_abort hook 路由到 ghost trampoline
 *
 * 由此 ArtMethod 字段 entry_point 不动、目标 .text 字节零修改——RASP「mem-vs-disk」
 * 比对、ArtMethod 漫游均零痕迹。
 *
 * 返回 ghost 内 backup_va（KPM 写好的 PC-relative-already-fixed clone 首指令地址）；
 * lsplant Java 路径不调它（invoke target 直接走 .oat trap），ArtMethod backup
 * call-original 也不经此（用 backup ArtMethod 走它自己的 entry_point）。 */
extern "C" void *shadowhook_pte_install_for_lsplant(void *target, void *hooker);

/* [M4b.3 R1+R2 P1] _ex 版回传 slot_idx + uninstall 由 DoUnHook 调拆 KPM slot 或 Dobby:
 *   - slot_idx>=0 ：PTE 主路径成功
 *   - slot_idx==-2：Dobby fallback（DoUnHook 须传 target VA 让 DobbyDestroy 用）
 *   - slot_idx==-1：完全失败（DoHook 应 return false） */
extern "C" void *shadowhook_pte_install_for_lsplant_ex(void *target, void *hooker,
                                                       int *out_slot_idx);
extern "C" long shadowhook_pte_uninstall_for_lsplant(int slot_idx, void *target_va_for_dobby);

/* M4b-Polish I3 (P1-F structural limit fix): DoUnHook 失败时标记 KPM slot 为 stuck
 * (PTE 仍 UXN-armed + do_mem_abort handler 仍服务防 SIGSEGV). 仅 telemetry. */
extern "C" void shadowhook_pte_force_recycle_slot_for_lsplant(int slot_idx);

#ifdef LSPLANT_M6_BACKEND
/* M6b: PTE/UXN hook wrappers in bridge/lsplant_glue.cpp.
 * install:        target_oat_va=OAT VA; trampoline_va=lsplant ghost ep;
 *                 *slot_out=bridge slot idx (≥0=success). Returns 0 on success.
 * smart_uninstall: bridge_slot_idx≥0; backup_ep=ART interp bridge VA.
 *                  Returns 0=full, 1=partial, <0=error.
 * rehook_redirect: bridge_slot_idx≥0; new_redirect_va=new trampoline ep.
 *                  Returns 0=success, <0=error.
 * uninstall (compat shim): delegates to smart_uninstall(backup_ep=orig_va). */
extern "C" int shadowhook_m6_install_for_lsplant(void *target_oat_va,
                                                   void *trampoline_va,
                                                   int32_t *slot_out);
extern "C" int shadowhook_m6_register_slot_for_lsplant(void *art_method,
                                                        void *target_oat_va,
                                                        void *trampoline_va,
                                                        int32_t *slot_out);
extern "C" int shadowhook_m6_is_stageable(void *target_oat_va);
extern "C" int shadowhook_m6_smart_uninstall_for_lsplant(int32_t bridge_slot_idx,
                                                           uint64_t backup_ep);
extern "C" int shadowhook_m6_rehook_redirect_for_lsplant(int32_t bridge_slot_idx,
                                                          uint64_t new_redirect_va);
extern "C" int shadowhook_m6_uninstall_for_lsplant(int32_t slot_idx);  /* compat */

/* M6b /apex/ 系统类 entry_point fallback 的命名 shim 分配器（bridge/lsplant_glue.cpp）。
 * make: 返回 [anon:dalvik-jit-code-cache] 命名 shim VA（BR 跳 real_trampoline），失败 nullptr。
 * free: munmap shim 页。 */
extern "C" void *shadowhook_m6_make_named_shim(void *real_trampoline);
extern "C" void  shadowhook_m6_free_named_shim(void *shim_va);

/* EP Spoof: 注册/注销 entry_point 字段地址 → 原始 OAT VA 映射（bridge + KPM 双侧）。
 * 在 DoHook fallback 路径（shim 替换 entry_point）后调 register，
 * 在 DoUnHook fallback 路径（还原 entry_point）前调 unregister。 */
extern "C" void shadowhook_ep_spoof_register(uintptr_t ep_field_addr, uint64_t original_ep);
extern "C" void shadowhook_ep_spoof_unregister(uintptr_t ep_field_addr);

/* OAT 页邻居 pass-through：SetEntryPointsToInterpreter(backup) 成功后捕获的
 * art_quick_to_interpreter_bridge VA。bridge 层传给 KPM fault handler，用于
 * M6b 页命中但无 slot 匹配时重定向到解释器（修 OAT 页污染问题）。 */
extern "C" void *g_lsplant_interp_bridge_va = nullptr;
#endif  /* LSPLANT_M6_BACKEND */

/* ArtMethod entry_point 字段偏移（ART 符号探测得到，不硬编码布局）。
 * 无条件定义：bridge 检测器（art_method_detector）经弱符号读取做严格判定——
 * 此前定义只在 LSPLANT_M6_BACKEND（已退役）分支内，正常构建里弱符号悬空，
 * 检测器的严格档被静默跳过。正常 InitNative 在 ArtMethod::Init 后赋值。 */
extern "C" uint32_t g_lsplant_art_method_entry_offset = 0;

module lsplant;

import dex_builder;

import :common;
import :art_method;
import :clazz;
import :thread;
import :instrumentation;
import :runtime;
import :thread_list;
import :class_linker;
import :scope_gc_critical_section;
import :jit_code_cache;
import :jni_id_manager;
import :dex_file;
import :jit;

namespace lsplant {

using art::ArtMethod;
using art::ClassLinker;
using art::DexFile;
using art::Instrumentation;
using art::Runtime;
using art::Thread;
using art::gc::ScopedGCCriticalSection;
using art::jit::Jit;
using art::jit::JitCodeCache;
using art::jni::JniIdManager;
using art::mirror::Class;
using art::thread_list::ScopedSuspendAll;
using art::JavaDebuggableGuard;

using namespace std::string_view_literals;

namespace {
/*
 * Hook bookkeeping remains published until the physical backend transition
 * succeeds.  Serialize the complete public mutation transaction (including
 * JNI GlobalRef and kInternalMethods housekeeping), otherwise two concurrent
 * UnHook callers can both snapshot the same record and free it twice after
 * taking SuspendAll in sequence.
 */
std::mutex &HookTransactionMutex() {
    static std::mutex instance;
    return instance;
}

/* A publisher may have made the candidate visible before it reports failure
 * (or before the bridge converts a pending JNI/C++ exception into failure).
 * Always give it an idempotent NULL rollback notification. JNI normally
 * suppresses calls while an exception is pending, so temporarily clear and
 * later restore the original throwable; an exception raised by rollback must
 * never replace the failure that caused rollback. */
void RollbackBackupPublication(
    JNIEnv *env, const std::function<bool(jobject)> &publisher) noexcept {
    jthrowable original_exception = nullptr;
    if (env && env->ExceptionCheck()) {
        original_exception = env->ExceptionOccurred();
        env->ExceptionClear();
    }

    try {
        if (!publisher(nullptr)) {
            LOGE("Backup publisher rejected rollback notification");
        }
    } catch (...) {
        /* A third-party C++ callback must not unwind across LSPlant. */
        LOGE("Backup publisher threw during rollback notification");
    }

    /* A rollback callback is cleanup-only. Never let a new exception escape
     * from it, whether or not there was an original publisher exception. */
    if (env && env->ExceptionCheck()) env->ExceptionClear();
    if (original_exception) {
        if (env->Throw(original_exception) != JNI_OK) {
            LOGE("Failed to restore publisher JNI exception after rollback");
        }
        env->DeleteLocalRef(original_exception);
    }
}

#if defined(LSPLANT_SKIP_ENTRY_POINT_PATCH) && !defined(LSPLANT_M6_BACKEND)
/*
 * Reserve the target key before the PTE backend is touched.  The backend makes
 * the hook executable before it returns, so inserting the record afterwards
 * leaves an allocation-failure window in which no later UnHook can find the
 * live slot.  Updating an existing node does not grow the hash table.
 */
bool PreparePteHookRecord(art::ArtMethod *target,
                          uint64_t original_oat_va) noexcept {
    try {
        return pte_hook_slots_()
            .insert({target, PteHookRecord{
                SHADOWHOOK_SLOT_INVALID, original_oat_va}})
            .second;
    } catch (...) {
        return false;
    }
}

bool PublishPteHookRecord(art::ArtMethod *target, int32_t slot) noexcept {
    bool updated = false;
    try {
        const bool found = pte_hook_slots_().modify_if(target, [&](auto &it) {
            if (it.second.slot_idx == SHADOWHOOK_SLOT_INVALID) {
                it.second.slot_idx = slot;
                updated = true;
            }
        });
        return found && updated;
    } catch (...) {
        return false;
    }
}

void ForgetReservedPteHookRecord(art::ArtMethod *target) noexcept {
    try {
        (void)pte_hook_slots_().erase_if(target, [](const auto &it) {
            return it.second.slot_idx == SHADOWHOOK_SLOT_INVALID;
        });
    } catch (...) {
        /* The process is already inside a terminal allocation/locking failure.
         * The reserved record has no live backend slot and is safe to retain. */
    }
}
#endif

template <typename T, T... chars>
inline consteval auto operator""_uarr() {
    return std::array<uint8_t, sizeof...(chars)>{static_cast<uint8_t>(chars)...};
}

consteval inline auto GetTrampoline() {
    if constexpr (is_arch_v<Arch::kArm>) {
        return std::make_tuple("\x00\x00\x9f\xe5\x00\xf0\x90\xe5\x78\x56\x34\x12"_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{32u}, uintptr_t{8u});
    }
    if constexpr (is_arch_v<Arch::kAArch64>) {
        return std::make_tuple(
            "\x60\x00\x00\x58\x10\x00\x40\xf8\x00\x02\x1f\xd6\x78\x56\x34\x12\x78\x56\x34\x12"_uarr,
            // NOLINTNEXTLINE
            uint8_t{44u}, uintptr_t{12u});
    }
    if constexpr (is_arch_v<Arch::kX86>) {
        return std::make_tuple("\xb8\x78\x56\x34\x12\xff\x70\x00\xc3"_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{56u}, uintptr_t{1u});
    }
    if constexpr (is_arch_v<Arch::kAmd64>) {
        return std::make_tuple("\x48\xbf\x78\x56\x34\x12\x78\x56\x34\x12\xff\x77\x00\xc3"_uarr,
                               // NOLINTNEXTLINE
                               uint8_t{96u}, uintptr_t{2u});
    }
    if constexpr (is_arch_v<Arch::kRiscv64>) {
        return std::make_tuple(
            "\x17\x05\x00\x00\x03\x35\x05\x01\x83\x3f\x05\x00\x67\x80\x0f\x00\x78\x56\x34\x12\x78\x56\x34\x12"_uarr,
            // NOLINTNEXTLINE
            uint8_t{84u}, uintptr_t{16u});
    }
}

auto [trampoline, entry_point_offset, art_method_offset] = GetTrampoline();

jmethodID method_get_name = nullptr;
jmethodID method_get_declaring_class = nullptr;
jmethodID class_get_name = nullptr;
jmethodID class_get_class_loader = nullptr;
jmethodID class_get_declared_constructors = nullptr;
jfieldID class_access_flags = nullptr;
jmethodID dex_file_init_with_cl = nullptr;
jmethodID dex_file_init = nullptr;
jmethodID load_class = nullptr;
jmethodID set_accessible = nullptr;
jclass executable = nullptr;

// for proxy method
jmethodID method_get_parameter_types = nullptr;
jmethodID method_get_return_type = nullptr;
// for old platform
jmethodID path_class_loader_init = nullptr;

constexpr auto kInternalMethods = std::make_tuple(
    &method_get_name, &method_get_declaring_class, &class_get_name, &class_get_class_loader,
    &class_get_declared_constructors, &dex_file_init, &dex_file_init_with_cl, &load_class,
    &set_accessible, &method_get_parameter_types, &method_get_return_type, &path_class_loader_init);

std::string generated_class_name;
std::string generated_source_name;
std::string generated_field_name;
std::string generated_method_name;

// shadowhook：保存 InitInfo 的 mem_map/mem_unmap（InitConfig 时复制）。
// GenerateTrampolineFor 不接收 InitInfo，故用文件级 static 中转。
static InitInfo::MemMapFunType   g_mem_map   = nullptr;
static InitInfo::MemUnmapFunType g_mem_unmap = nullptr;

bool InitConfig(const InitInfo &info) {
    if (info.generated_class_name.empty()) {
        LOGE("generated class name cannot be empty");
        return false;
    }
    generated_class_name = info.generated_class_name;
    if (info.generated_field_name.empty()) {
        LOGE("generated field name cannot be empty");
        return false;
    }
    generated_field_name = info.generated_field_name;
    if (info.generated_method_name.empty()) {
        LOGE("generated method name cannot be empty");
        return false;
    }
    generated_method_name = info.generated_method_name;
    generated_source_name = info.generated_source_name;
    g_mem_map   = info.mem_map;
    g_mem_unmap = info.mem_unmap;
    return true;
}

bool InitJNI(JNIEnv *env) {
    int sdk_int = GetAndroidApiLevel();
    if (sdk_int >= __ANDROID_API_O__) {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, "java/lang/reflect/Executable"));
    } else {
        executable = JNI_NewGlobalRef(env, JNI_FindClass(env, "java/lang/reflect/AbstractMethod"));
    }
    if (!executable) {
        LOGE("Failed to find Executable/AbstractMethod");
        return false;
    }

    if (method_get_name = JNI_GetMethodID(env, executable, "getName", "()Ljava/lang/String;");
        !method_get_name) {
        LOGE("Failed to find getName method");
        return false;
    }
    if (method_get_declaring_class =
            JNI_GetMethodID(env, executable, "getDeclaringClass", "()Ljava/lang/Class;");
        !method_get_declaring_class) {
        LOGE("Failed to find getDeclaringClass method");
        return false;
    }
    if (method_get_parameter_types =
            JNI_GetMethodID(env, executable, "getParameterTypes", "()[Ljava/lang/Class;");
        !method_get_parameter_types) {
        LOGE("Failed to find getParameterTypes method");
        return false;
    }
    if (method_get_return_type =
            JNI_GetMethodID(env, JNI_FindClass(env, "java/lang/reflect/Method"), "getReturnType",
                            "()Ljava/lang/Class;");
        !method_get_return_type) {
        LOGE("Failed to find getReturnType method");
        return false;
    }
    auto clazz = JNI_FindClass(env, "java/lang/Class");
    if (!clazz) {
        LOGE("Failed to find Class");
        return false;
    }

    if (class_get_class_loader =
            JNI_GetMethodID(env, clazz, "getClassLoader", "()Ljava/lang/ClassLoader;");
        !class_get_class_loader) {
        LOGE("Failed to find getClassLoader");
        return false;
    }

    if (class_get_declared_constructors = JNI_GetMethodID(env, clazz, "getDeclaredConstructors",
                                                          "()[Ljava/lang/reflect/Constructor;");
        !class_get_declared_constructors) {
        LOGE("Failed to find getDeclaredConstructors");
        return false;
    }

    if (class_get_name = JNI_GetMethodID(env, clazz, "getName", "()Ljava/lang/String;");
        !class_get_name) {
        LOGE("Failed to find getName");
        return false;
    }

    if (class_access_flags = JNI_GetFieldID(env, clazz, "accessFlags", "I"); !class_access_flags) {
        LOGE("Failed to find Class.accessFlags");
        return false;
    }
    auto path_class_loader = JNI_FindClass(env, "dalvik/system/PathClassLoader");
    if (!path_class_loader) {
        LOGE("Failed to find PathClassLoader");
        return false;
    }
    if (path_class_loader_init = JNI_GetMethodID(env, path_class_loader, "<init>",
                                                 "(Ljava/lang/String;Ljava/lang/ClassLoader;)V");
        !path_class_loader_init) {
        LOGE("Failed to find PathClassLoader.<init>");
        return false;
    }
    auto dex_file_class = JNI_FindClass(env, "dalvik/system/DexFile");
    if (!dex_file_class) {
        LOGE("Failed to find DexFile");
        return false;
    }
    if (sdk_int >= __ANDROID_API_Q__) {
        dex_file_init_with_cl = JNI_GetMethodID(
            env, dex_file_class, "<init>",
            "([Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;[Ldalvik/system/DexPathList$Element;)V");
    } else if (sdk_int >= __ANDROID_API_O__) {
        dex_file_init = JNI_GetMethodID(env, dex_file_class, "<init>", "(Ljava/nio/ByteBuffer;)V");
    }
    if (sdk_int >= __ANDROID_API_O__ && !dex_file_init_with_cl && !dex_file_init) {
        LOGE("Failed to find DexFile.<init>");
        return false;
    }
    if (load_class =
            JNI_GetMethodID(env, dex_file_class, "loadClass",
                            "(Ljava/lang/String;Ljava/lang/ClassLoader;)Ljava/lang/Class;");
        !load_class) {
        LOGE("Failed to find a suitable way to load class");
        return false;
    }
    auto accessible_object = JNI_FindClass(env, "java/lang/reflect/AccessibleObject");
    if (!accessible_object) {
        LOGE("Failed to find AccessibleObject");
        return false;
    }
    if (set_accessible = JNI_GetMethodID(env, accessible_object, "setAccessible", "(Z)V");
        !set_accessible) {
        LOGE("Failed to find AccessibleObject.setAccessible");
        return false;
    }
    return true;
}

inline void UpdateTrampoline(uint8_t offset) {
    trampoline[entry_point_offset / CHAR_BIT] |= offset << (entry_point_offset % CHAR_BIT);
    trampoline[entry_point_offset / CHAR_BIT + 1] |=
        offset >> (CHAR_BIT - entry_point_offset % CHAR_BIT);
}

#ifdef LSPLANT_M6_BACKEND
/* Stripped-down InitNative for M6b mode.
 * InitNative also initializes ScopedSuspendAll, Thread, Runtime, ClassLinker
 * (full), and JitCodeCache — all of which install Dobby inline hooks on
 * libart symbols, modifying libart .text and defeating M6b's zero-modification
 * goal.  M6b only needs ArtMethod field offsets (no hooks on API 33), the
 * Runtime::instance_ pointer (for JavaDebuggableGuard in ClassLinker::InitM6b),
 * and the interpreter bridge symbol.
 *
 * Call order: ArtMethod::Init → UpdateTrampoline → Runtime::Init →
 *             ClassLinker::InitM6b.
 * Runtime::Init uses only .as<> symbol lookups (no Dobby hooks).
 * The UpdateTrampoline call bakes the ArtMethod entry_point offset into the
 * trampoline byte array so that GenerateTrampolineFor produces correct patches
 * for the hook ArtMethod's entry_point field. */
bool InitNativeM6b(JNIEnv *env, const HookHandler &handler) {
    /* These three helpers are symbol-only Function<> resolvers; unlike ART
     * Hooker<> members they do not call info.inline_hooker or patch libart.
     * They let the final whole-page UXN transition stop other mutators. */
    if (!ScopedSuspendAll::Init(handler) ||
        !Thread::Init(handler) ||
        !ScopedGCCriticalSection::Init(handler)) {
        LOGE("M6b: Failed to init commit suspension helpers");
        return false;
    }
    if (!ArtMethod::Init(env, handler)) {
        LOGE("M6b: Failed to init ArtMethod");
        return false;
    }
    g_lsplant_art_method_entry_offset = ArtMethod::GetEntryPointOffset();
    if (g_lsplant_art_method_entry_offset == 0 ||
        g_lsplant_art_method_entry_offset > 128) {
        LOGE("M6b: invalid ArtMethod entry-point offset");
        return false;
    }
    UpdateTrampoline(ArtMethod::GetEntryPointOffset());
    /* Runtime::Init resolves instance_ and SetJavaDebuggable_ via .as<> only.
     * ClassLinker::InitM6b's JavaDebuggableGuard requires instance_ to be set. */
    if (!Runtime::Init(handler)) {
        LOGE("M6b: Failed to init Runtime");
        return false;
    }
    if (!ClassLinker::InitM6b(env, handler)) {
        LOGE("M6b: Failed to init ClassLinker interpreter bridge");
        return false;
    }
    return true;
}
#endif  /* LSPLANT_M6_BACKEND */

bool InitNative(JNIEnv *env, const HookHandler &handler) {
    // ① Resolve ScopedSuspendAll ctor/dtor symbols FIRST (chicken-and-egg):
    // ScopedSuspendAll::Init() only installs 2 inline hooks on ART internals
    // (constructor_ and destructor_), which are NOT called during the App's
    // class-init storm, so these 2 hooks are race-safe without a guard.
    if (!ScopedSuspendAll::Init(handler)) {
        LOGE("Failed to init scoped suspend all");
        return false;
    }
    // ② M4b.4-fu: stop-the-world guard for the remaining inline-hook installation.
    // When LSPlant is dlopen()-injected into a running multi-threaded App,
    // Dobby's non-atomic 22–24-byte prologue writes on libart symbols
    // (FixupStaticTrampolines*, ClassLinker::InitializeClass, etc.) race with
    // App threads already executing those functions during a class-init storm,
    // causing garbage SP/LR control flow → SIGSEGV.
    // long_suspend=false: estimated duration ~150–300 µs (35 hooks × ~5–10 µs),
    // far below the 5 s ANR threshold.
    ScopedSuspendAll guard("LSPlant InitNative", false);
    if (!ArtMethod::Init(env, handler)) {
        LOGE("Failed to init art method");
        return false;
    }
    /* 非 M6 路径同样发布 entry_point 偏移：检测器（art_method_detector 弱符号）
     * 的严格判定档依赖它；定义已移出 M6 ifdef，这里完成唯一赋值。 */
    g_lsplant_art_method_entry_offset = ArtMethod::GetEntryPointOffset();
    UpdateTrampoline(ArtMethod::GetEntryPointOffset());
    if (!Thread::Init(handler)) {
        LOGE("Failed to init thread");
        return false;
    }
    if (!Class::Init(handler)) {
        LOGE("Failed to init mirror class");
        return false;
    }
    if (!Runtime::Init(handler)) {
        LOGE("Failed to init runtime");
        return false;
    }
    if (!ClassLinker::Init(env, handler)) {
        LOGE("Failed to init class linker");
        return false;
    }
    if (!ScopedGCCriticalSection::Init(handler)) {
        LOGE("Failed to init scoped gc critical section");
        return false;
    }
    if (!JitCodeCache::Init(handler)) {
        LOGE("Failed to init jit code cache");
        return false;
    }
    if (!Jit::Init(handler)) {
        LOGE("Failed to init jit");
        return false;
    }
    if (!DexFile::Init(env, handler)) {
        LOGE("Failed to init dex file");
        return false;
    }
    if (!Instrumentation::Init(env, handler)) {
        LOGE("Failed to init instrumentation");
        return false;
    }
    if (!JniIdManager::Init(env, handler)) {
        LOGE("Failed to init jni id manager");
        return false;
    }

    // This should always be the last one
    if (IsJavaDebuggable(env)) {
        // Make the runtime non-debuggable as a workaround
        // when ShouldUseInterpreterEntrypoint inlined
        Runtime::Current()->SetJavaDebuggable(Runtime::RuntimeDebugState::kNonJavaDebuggable);
    }
    return true;
}

std::tuple<jclass, jfieldID, jmethodID, jmethodID> BuildDex(JNIEnv *env, jobject class_loader,
                                                            std::string_view shorty, bool is_static,
                                                            std::string_view method_name,
                                                            std::string_view hooker_class,
                                                            std::string_view callback_name) {
    // NOLINTNEXTLINE
    using namespace startop::dex;

    if (shorty.empty()) {
        LOGE("Invalid shorty");
        return {nullptr, nullptr, nullptr, nullptr};
    }

    DexBuilder dex_file;

    auto parameter_types = std::vector<TypeDescriptor>();
    parameter_types.reserve(shorty.size() - 1);
    auto return_type =
        shorty[0] == 'L' ? TypeDescriptor::Object : TypeDescriptor::FromDescriptor(shorty[0]);
    if (!is_static) parameter_types.push_back(TypeDescriptor::Object);  // this object
    for (const char &param : shorty.substr(1)) {
        parameter_types.push_back(param == 'L'
                                      ? TypeDescriptor::Object
                                      : TypeDescriptor::FromDescriptor(static_cast<char>(param)));
    }

    ClassBuilder cbuilder{dex_file.MakeClass(generated_class_name)};
    if (!generated_source_name.empty()) cbuilder.set_source_file(generated_source_name);

    auto hooker_type = TypeDescriptor::FromClassname(hooker_class.data());

    auto *hooker_field = cbuilder.CreateField(generated_field_name, hooker_type)
                             .access_flags(dex::kAccStatic)
                             .Encode();

    auto hook_builder{cbuilder.CreateMethod(
        generated_method_name == "{target}"sv ? method_name.data() : generated_method_name,
        Prototype{return_type, parameter_types})};
    // allocate tmp first because of wide
    auto tmp{hook_builder.AllocRegister()};
    hook_builder.BuildConst(tmp, static_cast<int>(parameter_types.size()));
    auto hook_params_array{hook_builder.AllocRegister()};
    hook_builder.BuildNewArray(hook_params_array, TypeDescriptor::Object, tmp);
    for (size_t i = 0U, j = 0U; i < parameter_types.size(); ++i, ++j) {
        hook_builder.BuildBoxIfPrimitive(Value::Parameter(j), parameter_types[i],
                                         Value::Parameter(j));
        hook_builder.BuildConst(tmp, static_cast<int>(i));
        hook_builder.BuildAput(Instruction::Op::kAputObject, hook_params_array, Value::Parameter(j),
                               tmp);
        if (parameter_types[i].is_wide()) ++j;
    }
    auto handle_hook_method{dex_file.GetOrDeclareMethod(
        hooker_type, callback_name.data(),
        Prototype{TypeDescriptor::Object, TypeDescriptor::Object.ToArray()})};
    hook_builder.AddInstruction(
        Instruction::GetStaticObjectField(hooker_field->decl->orig_index, tmp));
    hook_builder.AddInstruction(
        Instruction::InvokeVirtualObject(handle_hook_method.id, tmp, tmp, hook_params_array));
    if (return_type == TypeDescriptor::Void) {
        hook_builder.BuildReturn();
    } else if (return_type.is_primitive()) {
        auto box_type{return_type.ToBoxType()};
        const ir::Type *type_def = dex_file.GetOrAddType(box_type);
        hook_builder.AddInstruction(Instruction::Cast(tmp, Value::Type(type_def->orig_index)));
        hook_builder.BuildUnBoxIfPrimitive(tmp, box_type, tmp);
        hook_builder.BuildReturn(tmp, false, return_type.is_wide());
    } else {
        const ir::Type *type_def = dex_file.GetOrAddType(return_type);
        hook_builder.AddInstruction(Instruction::Cast(tmp, Value::Type(type_def->orig_index)));
        hook_builder.BuildReturn(tmp, true);
    }
    auto *hook_method = hook_builder.Encode();

    auto backup_builder{cbuilder.CreateMethod("backup", Prototype{return_type, parameter_types})};
    if (return_type == TypeDescriptor::Void) {
        backup_builder.BuildReturn();
    } else if (return_type.is_wide()) {
        LiveRegister zero = backup_builder.AllocRegister();
        LiveRegister zero_wide = backup_builder.AllocRegister();
        backup_builder.BuildConstWide(zero, 0);
        backup_builder.BuildReturn(zero, /*is_object=*/false, true);
    } else {
        LiveRegister zero = backup_builder.AllocRegister();
        backup_builder.BuildConst(zero, 0);
        backup_builder.BuildReturn(zero, /*is_object=*/!return_type.is_primitive(), false);
    }
    auto *backup_method = backup_builder.Encode();

    slicer::MemView image{dex_file.CreateImage()};

    jclass target_class = nullptr;

    ScopedLocalRef<jobject> java_dex_file{nullptr};

    if (auto dex_file_class = JNI_FindClass(env, "dalvik/system/DexFile"); dex_file_init_with_cl) {
        java_dex_file = JNI_NewObject(
            env, dex_file_class, dex_file_init_with_cl,
            JNI_NewObjectArray(
                env, 1, JNI_FindClass(env, "java/nio/ByteBuffer"),
                JNI_NewDirectByteBuffer(env, const_cast<void *>(image.ptr()), image.size())),
            nullptr, nullptr);
    } else if (dex_file_init) {
        java_dex_file = JNI_NewObject(
            env, dex_file_class, dex_file_init,
            JNI_NewDirectByteBuffer(env, const_cast<void *>(image.ptr()), image.size()));
    } else {
        void *target =
            mmap(nullptr, image.size(), PROT_WRITE | PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
        memcpy(target, image.ptr(), image.size());
        mprotect(target, image.size(), PROT_READ);
        std::string err_msg;
        const auto *dex = DexFile::OpenMemory(
            reinterpret_cast<const uint8_t *>(target), image.size(),
            generated_source_name.empty() ? "lsplant" : generated_source_name, &err_msg);
        if (!dex) {
            LOGE("Failed to open memory dex: %s", err_msg.data());
        } else {
            java_dex_file = ScopedLocalRef(env, dex ? dex->ToJavaDexFile(env) : nullptr);
        }
    }

    if (auto path_class_loader = JNI_FindClass(env, "dalvik/system/PathClassLoader");
        java_dex_file) {
        auto my_cl = JNI_NewObject(env, path_class_loader, path_class_loader_init,
                                   JNI_NewStringUTF(env, "."), class_loader);
        target_class =
            JNI_Cast<jclass>(
                JNI_CallObjectMethod(env, java_dex_file, load_class,
                                     JNI_NewStringUTF(env, generated_class_name.data()), my_cl))
                .release();
    }

    if (target_class) {
        return {
            target_class,
            JNI_GetStaticFieldID(env, target_class, hooker_field->decl->name->c_str(),
                                 hooker_field->decl->type->descriptor->c_str()),
            JNI_GetStaticMethodID(env, target_class, hook_method->decl->name->c_str(),
                                  hook_method->decl->prototype->Signature().data()),
            JNI_GetStaticMethodID(env, target_class, backup_method->decl->name->c_str(),
                                  backup_method->decl->prototype->Signature().data()),
        };
    }
    return {nullptr, nullptr, nullptr, nullptr};
}

static_assert(std::endian::native == std::endian::little, "Unsupported architecture");

union Trampoline {
public:
    uintptr_t address;
    unsigned count4k : 12;
    unsigned count16k : 14;
};

static_assert(sizeof(Trampoline) == sizeof(uintptr_t), "Unsupported architecture");
static_assert(std::atomic_uintptr_t::is_always_lock_free, "Unsupported architecture");

std::atomic_uintptr_t trampoline_pool{0};
std::atomic_flag trampoline_lock{false};
constexpr size_t kTrampolineSize = RoundUpTo(sizeof(trampoline), kPointerSize);
const auto kPageSize = static_cast<size_t>(getpagesize());  // assume
const auto kPageMask = static_cast<uintptr_t>(kPageSize - 1);

void *GenerateTrampolineFor(art::ArtMethod *hook) {
    static const size_t kTrampolineNumPerPage = kPageSize / kTrampolineSize;
    unsigned count;
    uintptr_t address;
    while (true) {
        auto tl = Trampoline{.address = trampoline_pool.fetch_add(1, std::memory_order_release)};
        count = kPageSize == 16384 ? tl.count16k : tl.count4k;
        address = tl.address & ~kPageMask;
        if (address == 0 || count >= kTrampolineNumPerPage) {
            if (trampoline_lock.test_and_set(std::memory_order_acq_rel)) {
                trampoline_lock.wait(true, std::memory_order_acquire);
                continue;
            }
            void *tramp_page = g_mem_map
                ? g_mem_map(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)
                : mmap(nullptr, kPageSize, PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
            address = reinterpret_cast<uintptr_t>(tramp_page);
            if (address == reinterpret_cast<uintptr_t>(MAP_FAILED)) {
                PLOGE("mmap trampoline");
                trampoline_lock.clear(std::memory_order_release);
                trampoline_lock.notify_all();
                return nullptr;
            }
            count = 0;
            tl.address = address;
            kPageSize == 16384 ? tl.count16k = count + 1 : tl.count4k = count + 1;
            trampoline_pool.store(tl.address, std::memory_order_release);
            trampoline_lock.clear(std::memory_order_release);
            trampoline_lock.notify_all();
        }
        LOGV("trampoline: count = %u, address = %zx, target = %zx", count, address,
             address + count * kTrampolineSize);
        address = address + count * kTrampolineSize;
        break;
    }
    auto *address_ptr = reinterpret_cast<char *>(address);
    std::memcpy(address_ptr, trampoline.data(), trampoline.size());

    *reinterpret_cast<art::ArtMethod **>(address_ptr + art_method_offset) = hook;

    __builtin___clear_cache(address_ptr, reinterpret_cast<char *>(address + trampoline.size()));

    return address_ptr;
}

#ifdef LSPLANT_M6_BACKEND
/*
 * Backend rollback 出现不确定结果后保持 sticky-false，直到进程退出。继续执行
 * ARM_PAGES 可能把一个 caller 已看到“Hook 失败”的 redirect 发布出去，因此这里
 * 宁可拒绝整个后续 transaction，也不尝试猜测单个 slot 的内核状态。
 */
std::atomic<bool> g_m6_transaction_healthy{true};

enum class M6RollbackDisposition {
    kRemoved,
    kPassThrough,
    kPoisoned,
};

bool ReadM6HookRecord(ArtMethod *target, M6HookRecord *out) noexcept {
    if (!out) return false;
    try {
        return m6_hook_slots_().if_contains(
            target, [out](const auto &it) { *out = it.second; });
    } catch (...) {
        g_m6_transaction_healthy.store(false, std::memory_order_release);
        return false;
    }
}

bool PrepareM6HookRecord(ArtMethod *target, uint64_t target_oat_va) noexcept {
    try {
        return m6_hook_slots_()
            .insert({target, M6HookRecord{
                -1, target_oat_va, false, 0, M6HookRecord::State::kRegistering}})
            .second;
    } catch (...) {
        return false;
    }
}

bool TransitionM6HookRecord(ArtMethod *target, int32_t slot,
                            M6HookRecord::State state) noexcept {
    bool updated = false;
    try {
        bool found = m6_hook_slots_().modify_if(target, [&](auto &it) {
            /* 注册发布只允许 -1 → slot；之后的状态迁移必须仍指向同一 bridge slot。
             * 这也防住同 target 非法并发 Hook 把另一笔 transaction 的记录改坏。 */
            if ((it.second.state == M6HookRecord::State::kRegistering &&
                 it.second.slot_idx == -1) ||
                it.second.slot_idx == slot) {
                it.second.slot_idx = slot;
                it.second.state = state;
                updated = true;
            }
        });
        return found && updated;
    } catch (...) {
        return false;
    }
}

bool EraseM6HookRecord(ArtMethod *target, int32_t slot) noexcept {
    try {
        return m6_hook_slots_().erase_if(target, [slot](const auto &it) {
            return it.second.slot_idx == slot ||
                   (slot >= 0 &&
                    it.second.state == M6HookRecord::State::kRegistering &&
                    it.second.slot_idx == -1);
        });
    } catch (...) {
        return false;
    }
}

void PoisonM6Transaction(ArtMethod *target, int32_t slot) noexcept {
    /* 状态写失败也不能重新开放 transaction：atomic sticky gate 是最终防线。 */
    (void)TransitionM6HookRecord(target, slot, M6HookRecord::State::kPoisoned);
    g_m6_transaction_healthy.store(false, std::memory_order_release);
}

M6RollbackDisposition RollbackM6Registration(ArtMethod *target, int32_t slot,
                                              uint64_t pass_through_ep) noexcept {
    int rc = shadowhook_m6_smart_uninstall_for_lsplant(slot, pass_through_ep);
    if (rc == 0) {
        /* 只有 backend 明确完成 full uninstall 才允许删除 slot 元数据。 */
        if (EraseM6HookRecord(target, slot)) return M6RollbackDisposition::kRemoved;
        PoisonM6Transaction(target, slot);
        return M6RollbackDisposition::kPoisoned;
    }
    if (rc == 1) {
        /* 同页仍武装：KPM 已把该 method 改为解释器 pass-through，保留 slot
         * 供下一次 Hook 走 rehook_redirect。 */
        if (TransitionM6HookRecord(
                target, slot, M6HookRecord::State::kPassThrough)) {
            return M6RollbackDisposition::kPassThrough;
        }
        PoisonM6Transaction(target, slot);
        return M6RollbackDisposition::kPoisoned;
    }

    /* rc<0 表示既不能证明 slot 已删除，也不能证明已安全 pass-through。保留
     * m6_hook_slots_ + hooked_methods_ + GlobalRef，并阻断后续 ARM_PAGES。 */
    PoisonM6Transaction(target, slot);
    return M6RollbackDisposition::kPoisoned;
}
#endif

bool DoHook(ArtMethod *target, ArtMethod *hook, ArtMethod *backup,
            const art::dex::ClassDef *hooked_class_def,
            const art::dex::ClassDef *deoptimized_class_def,
            bool is_proxy,
            jobject reflected_backup, jmethodID backup_jmethodid,
            jmethodID target_jmethodid, bool *out_recorded) {
    if (out_recorded) *out_recorded = false;
    /* M6's symbol-only InitNativeM6b initializes these helpers without
     * patching libart. ArtMethod::BackupTo/CopyFrom and access-flag changes
     * must therefore obey the same stop-the-world contract as normal LSPlant. */
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant Hook", false);
    LOGV("Hooking: target = %s(%p), hook = %s(%p), backup = %s(%p)", target->PrettyMethod().c_str(),
         target, hook->PrettyMethod().c_str(), hook, backup->PrettyMethod().c_str(), backup);

    /* Publish all fallible bookkeeping while the same SuspendAll boundary that
     * protects ArtMethod mutation is active, but before touching either method.
     * This prevents a concurrent class-initialization callback from observing a
     * hooked_classes_ entry whose target still has the old entry point. */
    if (!RecordHooked(target, hooked_class_def, reflected_backup, backup,
                      backup_jmethodid, target_jmethodid)) {
        LOGE("Failed to record hook transaction");
        return false;
    }
    if (out_recorded) *out_recorded = true;

    HookAuxRecords aux_records{};
#ifndef LSPLANT_M6_BACKEND
    if (!RecordHookAuxRecords(
            target, backup, is_proxy, deoptimized_class_def, &aux_records)) {
        LOGE("Failed to reserve auxiliary hook bookkeeping");
        ForgetHookedRecord(target, hooked_class_def, backup);
        if (out_recorded) *out_recorded = false;
        return false;
    }
#endif

    struct HookRecordGuard {
        ArtMethod *target;
        const art::dex::ClassDef *class_def;
        const art::dex::ClassDef *deoptimized_class_def;
        ArtMethod *backup;
        HookAuxRecords *aux_records;
        bool *out_recorded;
        uint32_t original_access_flags;
        bool committed = false;

        ~HookRecordGuard() {
            if (committed) return;
#ifdef LSPLANT_M6_BACKEND
            /* An ambiguous backend rollback intentionally retains the record
             * and GlobalRef for UnHookAll/restart containment. */
            if (!g_m6_transaction_healthy.load(std::memory_order_acquire)) return;
#endif
            /* SetNonIntrinsic/BackupTo/SetNonCompilable only mutate the target's
             * access flags before the backend's commit point.  Restore the exact
             * pre-transaction value on every definite failure so a rejected Hook
             * has no residual ArtMethod mutation. */
            target->SetAccessFlags(original_access_flags);
            ForgetHookAuxRecords(
                target, backup, deoptimized_class_def, aux_records);
            ForgetHookedRecord(target, class_def, backup);
            if (out_recorded) *out_recorded = false;
        }
    } record_guard{target, hooked_class_def, deoptimized_class_def, backup,
                   &aux_records, out_recorded, target->GetAccessFlags()};

#ifdef LSPLANT_M6_BACKEND
    if (!g_m6_transaction_healthy.load(std::memory_order_acquire)) {
        LOGE("M6b DoHook: transaction poisoned; process restart required");
        return false;
    }

    M6HookRecord existing_m6_record{};
    const bool has_existing_m6_record =
        ReadM6HookRecord(target, &existing_m6_record);
    if (!g_m6_transaction_healthy.load(std::memory_order_acquire)) {
        LOGE("M6b DoHook: unable to read transaction metadata");
        return false;
    }
    if (has_existing_m6_record &&
        (existing_m6_record.slot_idx < 0 ||
         existing_m6_record.state != M6HookRecord::State::kPassThrough)) {
        /* 正常 rehook 只可能来自 rc=1 的 pass-through。其它残留状态表示
         * hooked_methods_ 与 backend 元数据失配，不能继续生成/提交新 redirect。 */
        PoisonM6Transaction(target, existing_m6_record.slot_idx);
        LOGE("M6b DoHook: stale non-pass-through slot metadata");
        return false;
    }

    /* Fail before GenerateTrampoline/BackupTo/access-flag mutation.  System
     * boot-image and interpreter entry points have no staged Pixel 6 backend;
     * the former shim fallback published too early and is intentionally gone.
     *
     * rehook 特例：rc<0 / partial UnHook 之后，target 当前 entry_point 可能已被
     * 临时切到 interpreter pass-through。此时真正要重新武装的仍是原始 OAT VA，
     * 必须用 existing_m6_record.original_oat_va 判 stageable，而不是看当前
     * target->GetEntryPoint()。 */
    void *stageable_ep = has_existing_m6_record
        ? reinterpret_cast<void *>(existing_m6_record.original_oat_va)
        : target->GetEntryPoint();
    if (!shadowhook_m6_is_stageable(stageable_ep)) {
        LOGE("M6b DoHook: target entry point is not stageable");
        return false;
    }
#endif

    if (auto *entrypoint = GenerateTrampolineFor(hook); !entrypoint) {
        LOGE("Failed to generate trampoline");
        return false;
        // NOLINTNEXTLINE
    } else {
        LOGV("Generated trampoline %p", entrypoint);

        target->SetNonIntrinsic();

        target->BackupTo(backup);

        target->SetNonCompilable();

#ifdef LSPLANT_M6_BACKEND
        /* ============================================================
         * M6b PTE/UXN 主路径：直接在 OAT/JIT 页 PTE.UXN=1；不改 ArtMethod.entry_point。
         * 不需要 Dobby (InitNative 被 Init() 跳过)。
         *
         * 顺序：
         *   1. 保存 target 原 OAT entry_point（BackupTo 之前，尚未被覆写）。
         *   2. 调 shadowhook_m6_install_for_lsplant：KPM SH_CMD_M6_SIMPLE_HOOK
         *      把 OAT 页 PTE.UXN=1；fault 时改 pc → trampoline（GenerateTrampolineFor(hook)）。
         *   3. 把 backup 的 entry_point 改成 ART interpreter 入口
         *      (ClassLinker::SetEntryPointsToInterpreter)，使 cb.backup.invoke() 走
         *      DEX bytecode 执行，而不经过 UXN-armed OAT 页（避免重入 hook）。
         *   4. 记录 (target → {slot_idx, original_oat_va}) 供 DoUnHook 还原。
         * ============================================================ */

        /* Step 0: is_rehook 检测——Phase C 场景下，target 曾被 partial UnHook，
         * m6_hook_slots_ 仍保有 bridge_slot_idx 记录；直接更新 redirect_va 即可，
         * 无需重新 install（KPM slot 和 UXN 仍在位）。
         *
         * L4 路径补强：DoUnHook 的 smart_uninstall error 分支会让 target 暂时走
         * interpreter bridge（避免误跳已释放 trampoline），因此 rehook 时必须把
         * target.entry_point 明确改回 original_oat_va；否则仅更新 redirect_va，
         * target 仍停在解释执行路径，UXN trap 永远不会再命中。 */
        {
            const int32_t existing_bridge_slot =
                has_existing_m6_record ? existing_m6_record.slot_idx : -1;
            const uint64_t existing_orig_va =
                has_existing_m6_record ? existing_m6_record.original_oat_va : 0;
            if (existing_bridge_slot >= 0) {
                /* This DoHook created a fresh backup ArtMethod above.  Make
                 * that backup callable before staging the KPM redirect; if
                 * ART refuses, the existing pass-through slot remains wholly
                 * untouched and the caller gets a real failure. */
                if (!backup->IsNative() &&
                    !ClassLinker::SetEntryPointsToInterpreter(backup)) {
                    LOGE("M6b DoHook rehook: SetEntryPointsToInterpreter(backup) failed");
                    return false;
                }
                if (!g_lsplant_interp_bridge_va) {
                    g_lsplant_interp_bridge_va = backup->GetEntryPoint();
                }
                int rc = shadowhook_m6_rehook_redirect_for_lsplant(
                             existing_bridge_slot,
                             reinterpret_cast<uint64_t>(entrypoint));
                if (rc != 0) {
                    LOGE("M6b DoHook rehook: rehook_redirect_for_lsplant"
                         "(bridge=%d ep=%p) failed rc=%d",
                         existing_bridge_slot, entrypoint, rc);
                    return false;
                }
                if (!TransitionM6HookRecord(
                        target, existing_bridge_slot,
                        M6HookRecord::State::kStaged)) {
                    /* KPM 已进入 pending rehook；没有可靠 metadata 时绝不能让
                     * nativeEndHookBatch/commit_hooks 发布它。 */
                    PoisonM6Transaction(target, existing_bridge_slot);
                    LOGE("M6b DoHook rehook: failed to publish staged metadata");
                    return false;
                }
                /* target 的 entry_point 恢复到原 OAT VA：
                 *   - 常规 partial UnHook：它本来就还是 OAT VA，这里是 no-op；
                 *   - rc<0 error UnHook：target 可能已被临时切到 interp bridge，这里必须切回，
                 *     让后续 Java 调用重新命中 UXN trap。 */
                if (existing_orig_va != 0) {
                    target->SetEntryPoint(reinterpret_cast<void *>(existing_orig_va));
                }
                record_guard.committed = true;
                return true;
            }
        }

        /* Step 1: 捕获原始 OAT entry_point。
         * BackupTo() 已在上方执行，但它只改写 backup 的字段（CopyFrom）和 target 的
         * access_flags（SetNonCompilable / ClearFastInterpretFlag），不触碰 target 的
         * entry_point 字段，所以此处读到的仍是原始 OAT VA。 */
        uint64_t target_oat_va = reinterpret_cast<uint64_t>(target->GetEntryPoint());

        /* KPM syscall 前先预占 map 节点。register 成功后仅 modify_if 原位写 slot，
         * 不再经过任何可能 OOM 的 hash-table 分配窗口。 */
        if (!PrepareM6HookRecord(target, target_oat_va)) {
            LOGE("M6b DoHook: failed to reserve slot metadata");
            return false;
        }

        /* Step 2: 注册 M6 slot（延迟武装——UXN 由 nativeEndHookBatch 批量 arm）。
         * 延迟武装原因：Hooker.java 的 OAT continuation code（nativeInitAndHook JNI return 之后）
         * 与 Target.M1 entry 可能在同一 4KB OAT 页；若 DoHook 内立刻 arm UXN，
         * Hooker continuation 执行时触发 fault handler 但 VA 不在 slot 表 → SIGSEGV。
         * 解决：DoHook 仅注册 slot（不 arm），所有 Hooker.hook() 返回后统一 arm。 */
        int32_t m6_slot = -1;
        int m6_rc = shadowhook_m6_register_slot_for_lsplant(
            target, reinterpret_cast<void *>(target_oat_va), entrypoint, &m6_slot);
        if (m6_rc == SH_M6_OK && m6_slot >= 0) {
            /* register 成功后的第一项用户态动作：发布 bridge slot。 */
            if (!TransitionM6HookRecord(
                    target, m6_slot, M6HookRecord::State::kStaged)) {
                LOGE("M6b DoHook: registered slot metadata publish failed");
                (void)RollbackM6Registration(
                    target, m6_slot,
                    reinterpret_cast<uint64_t>(backup->GetEntryPoint()));
                return false;
            }
        }
        /* R2-CM-04 治本 (审计 Medium): 严格区分 SH_M6_E_INVAL (/apex/ VA 合法拒绝, 走
         * shim fallback) 与 SH_M6_E_NOSPC / 其他 (slot 表满 or 通用错误, 直接 return
         * false 不 fallback). 之前 `m6_rc != 0 || m6_slot < 0` 把两情况混, slot 满时
         * 也走 fallback 泄漏 shim 页 + 破坏 M6b 主路径承诺. */
        if (m6_rc == SH_M6_E_INVAL) {
            if (!EraseM6HookRecord(target, -1)) {
                PoisonM6Transaction(target, -1);
            }
            /* Pixel 6's staged backend cannot include the legacy /apex/
             * entry-point shim in ARM_PAGES: SetEntryPoint would publish the
             * hook immediately, before the Java/plugin transaction commits.
             * Reject system/boot-image methods explicitly until they have a
             * genuinely staged backend. */
            LOGE("M6b DoHook: target is not KPM-stageable; entry-point shim "
                 "fallback disabled on Pixel 6");
            return false;
#if 0
            /* ── /apex/ 系统类 entry_point fallback ──────────────────────────────
             * register_slot 明确以 SH_M6_E_INVAL 拒绝: target OAT VA 在 boot image
             * (/apex/, 跨进程共享, 不能 PTE/UXN). 回退到上游 LSPlant 原版机制——改
             * ArtMethod.entry_point。但不直指隐藏 ghost trampoline（会让检测器读到
             * entry_point 指向未映射内存 → -1 异常），而是经命名 shim 页 BR 跳转。
             * libart .text 零篡改保持（entry_point 在 LinearAlloc，不在 .text）。 */
            void *shim = shadowhook_m6_make_named_shim(entrypoint);
            if (!shim) {
                LOGE("M6b DoHook fallback: make_named_shim failed (target stays unhooked)");
                return false;
            }
            /* shadowhook audit LFD-3 fix: 顺序重排避免 rollback race——
             *   旧顺序: SetEntryPoint(shim) → SetEntryPointsToInterpreter(backup) → rollback
             *   问题:   步骤 1 后步骤 2 前, 其他 in-flight 线程可能通过 target.M() 已 dispatch
             *           到 shim → 跳 real_trampoline → callback 执行. 步骤 2 fail 后
             *           rollback 步骤 munmap shim → 悬空指针; 若还有线程在 shim 内 crash.
             *   新顺序: SetEntryPointsToInterpreter(backup) 先 → SetEntryPoint(shim) 最后
             *           SetEntryPointsToInterpreter fail 时 shim 还没 install, munmap 安全
             *           不会有线程执行 shim (target 仍在 boot OAT VA 上). 无需
             *           ScopedSuspendAll — 靠单一 SetEntryPoint 原子 store 实现最后 commit.
             *
             * native 方法: backup 走 JNI bridge, 不经 OAT/UXN 页, 无需改 interp; 但仍需
             * install shim 让 target 命中. 拆条件: interp fail 只在 !IsNative 才 fail-early. */
            if (!backup->IsNative() &&
                !ClassLinker::SetEntryPointsToInterpreter(backup)) {
                LOGE("M6b DoHook fallback: SetEntryPointsToInterpreter(backup) failed "
                     "— aborting install (target stays unhooked, safe to munmap shim)");
                shadowhook_m6_free_named_shim(shim);
                return false;
            }
            if (!g_lsplant_interp_bridge_va) {
                g_lsplant_interp_bridge_va = backup->GetEntryPoint();
            }
            /* 最后一步 (原子 commit): 设 target.entry_point = shim, 从此 target.M() 走 hook. */
            target->SetEntryPoint(shim);
            /* shadowhook audit LFD-1 (BLG-1) fix: phmap::insert 可能抛 bad_alloc (OOM);
             * 若抛且不 catch, C++ noexcept-across-JNI 未定义行为 (通常 abort 进程) + shim
             * 泄漏 + target entry_point 不回滚. try-catch 里出错 rollback:
             * 恢复 target.entry_point 到原 OAT VA, munmap shim, 返 false. */
            try {
                /* 记录 fallback：slot_idx=-1，shim_va 供 DoUnHook munmap。 */
                m6_hook_slots_().insert({target, M6HookRecord{
                    -1, target_oat_va, true, reinterpret_cast<uint64_t>(shim),
                    M6HookRecord::State::kStaged}});
                /* EP Spoof 注册：让 bridge + KPM 侧的 spoof 表知道此 ArtMethod+24 对应的
                 * 原始 OAT VA，RASP pread64 hook 拦截读 entry_point 字段时返回原始值。 */
                shadowhook_ep_spoof_register(
                    reinterpret_cast<uintptr_t>(target) + 24,
                    target_oat_va);
            } catch (const std::bad_alloc &) {
                LOGE("M6b DoHook fallback: phmap insert bad_alloc — rollback shim + entry_point");
                target->SetEntryPoint(reinterpret_cast<void *>(target_oat_va));
                shadowhook_m6_free_named_shim(shim);
                return false;
            }
            record_guard.committed = true;
            return true;
#endif
        }
        if (m6_rc != SH_M6_OK || m6_slot < 0) {
            if (!EraseM6HookRecord(target, -1)) {
                PoisonM6Transaction(target, -1);
            }
            /* R2-CM-04: 非 -EINVAL 类错误 (slot 表满 SH_M6_E_NOSPC / kallsyms 未 resolve
             * SH_M6_E_NOENT / 通用错误 SH_M6_E_GENERIC 等) 明确 return false 让 caller
             * 感知 hook 失败, 不静默走 shim fallback 掩盖 slot 表满等结构性问题. */
            LOGE("M6b DoHook: register_slot rc=%d (not -EINVAL, no fallback) - hook failed", m6_rc);
            return false;
        }

        /* Step 3: backup entry_point → ART interpreter
         * call_original (cb.backup.invoke) 走 interpreter DEX 路径，不触发 UXN trap。
         * ClassLinker::SetEntryPointsToInterpreter 由 import :class_linker 提供。
         * native 方法跳过——backup 走 JNI bridge，不经 OAT/UXN 页，无需改 interp。 */
        if (!backup->IsNative() &&
            !ClassLinker::SetEntryPointsToInterpreter(backup)) {
            LOGE("M6b DoHook: SetEntryPointsToInterpreter(backup) failed — rollback");
            (void)RollbackM6Registration(
                target, m6_slot,
                reinterpret_cast<uint64_t>(backup->GetEntryPoint()));
            return false;
        }
        if (!g_lsplant_interp_bridge_va) {
            g_lsplant_interp_bridge_va = backup->GetEntryPoint();
        }

        /* slot 元数据已在 register 后立即发布；此处无可分配/失败步骤。 */

#elif defined(LSPLANT_SKIP_ENTRY_POINT_PATCH)
        /* ============================================================
         * M4b PTE/UXN 主路径（shadowhook fork mod，bridge/CMakeLists.txt 经
         * `-DLSPLANT_SKIP_ENTRY_POINT_PATCH` 注入；M4a Dobby 原路径见 #else 分支）
         * ============================================================
         * 不改 target 的 ArtMethod.entry_point 字段（保留原 .oat 段地址）；改为
         * 显式调 shadowhook_pte_install_for_lsplant_ex 把 target.entry_point 指向的
         * .oat VA 作 PTE hook target，hooker = trampoline entrypoint（由 lsplant
         * GenerateTrampolineFor(hook) 生成；M4a 即 Dobby 走 ghost trampoline 页）。
         *
         * 此后 Java invoke target 走原 .oat 段 → CPU ifetch UXN trap → KPM
         * before_do_mem_abort → 改 pt_regs.pc 跳 ghost trampoline → callback。
         *
         * **[M4b.3 R1 P1-A 修] call-original 修复**：
         *   先前版本 `(void)pte_backup` 丢掉了 KPM 返的 ghost backup_va。问题：
         *   BackupTo(backup) 把 target 的字段（含 entry_point=.oat_va）拷给 backup；
         *   ArtMethod backup 仍指向 .oat 段；但 .oat 现在 PTE.UXN=1 → ART 调
         *   backup（即 call_original）会重入 hook → 递归。修法：把 backup 的
         *   entry_point 改成 ghost 里的 backup_va（DBI 已修过 PC-相对指令的原首
         *   指令位置），call_original 跳进 ghost 直接跑原指令，不触发 trap.
         *   ghost 页本身 UXN=0（独立 VMA），合法 exec.
         *
         * **[M4b.3 R1 P1-B 修] slot tracking**：
         *   _ex 版回传 slot_idx；存入 pte_hook_slots_(target) → DoUnHook 用同 key
         *   查回再调 shadowhook_pte_uninstall_for_lsplant 拆 KPM 端 slot. */
        uint64_t target_oat_va = reinterpret_cast<uint64_t>(target->GetEntryPoint());
        if (!PreparePteHookRecord(target, target_oat_va)) {
            LOGE("M4b PTE failed to reserve slot metadata before install");
            return false;
        }
        int pte_slot = SHADOWHOOK_SLOT_INVALID;
        void *pte_backup = shadowhook_pte_install_for_lsplant_ex(
                              reinterpret_cast<void *>(target_oat_va), entrypoint, &pte_slot);
        if (!pte_backup) {
            ForgetReservedPteHookRecord(target);
            LOGE("M4b PTE shadowhook_pte_install_for_lsplant_ex(.oat=%p, entrypoint=%p) failed slot=%d",
                 (void *)target_oat_va, entrypoint, pte_slot);
            return false;
        }
        /* [P1-A 修] PTE 路径让 call_original 走 ghost 而非 .oat trap (避免重入)；
         * Dobby fallback 路径 backup_va = Dobby origin (M4a 既有语义)，同样把 backup
         * 指过去 — 上游 M4a 既如此 (DobbyHook origin → backup entry_point)，沿用. */
        backup->SetEntryPoint(pte_backup);
        /* [P1-B+P1-C+P1-D 修] 跟踪 (slot_idx, original_oat_va) 供 DoUnHook:
         *   - PTE 主路径：DoUnHook 调 uninstall + 把 target.entry_point 还原到 original_oat_va
         *     (防 CopyFrom 把 pte_backup ghost VA 灌回 target，但 ghost 页已 free → 悬空崩)
         *   - Dobby fallback：DoUnHook 调 DobbyDestroy(target_oat_va) 拆 inline patch.
         * pte_slot == SHADOWHOOK_SLOT_INVALID 表 install 完全失败，但本路径 pte_backup==null
         * 已 return false，不会走到这里. */
        if (pte_slot >= 0 || pte_slot == SHADOWHOOK_SLOT_FALLBACK_DOBBY) {
            if (!PublishPteHookRecord(target, pte_slot)) {
                /* The key was reserved before install, so this path should
                 * only be reachable after an exceptional map failure.  Undo
                 * the now-live backend before returning failure. */
                long rollback_rc = -16;
                for (int retry = 0; retry < 4 && rollback_rc == -16; ++retry) {
                    rollback_rc = shadowhook_pte_uninstall_for_lsplant(
                        pte_slot, reinterpret_cast<void *>(target_oat_va));
                    if (rollback_rc == -16) sched_yield();
                }
                if (rollback_rc == 0) {
                    ForgetReservedPteHookRecord(target);
                } else {
                    /* Returning would expose a live hook whose bookkeeping
                     * could not be published.  Keep the process inside this
                     * stack frame and fail-stop instead. */
                    LOGE("M4b PTE backend rollback remained ambiguous");
                    std::abort();
                }
                LOGE("M4b PTE slot metadata publish failed; backend rollback rc=%ld",
                     rollback_rc);
                return false;
            }
        } else {
            /* A non-null backup means the backend may already be active, but
             * without a valid slot id it cannot be restored or tracked. */
            LOGE("M4b PTE install returned an invalid slot id");
            std::abort();
        }
#else
        target->SetEntryPoint(entrypoint);   /* M4a 原路径：改 entry_point 到 trampoline */
#endif

        LOGV("Done hook: target(%p:0x%x) -> %p; backup(%p:0x%x) -> %p; hook(%p:0x%x) -> %p", target,
             target->GetAccessFlags(), target->GetEntryPoint(), backup, backup->GetAccessFlags(),
             backup->GetEntryPoint(), hook, hook->GetAccessFlags(), hook->GetEntryPoint());

        record_guard.committed = true;
        return true;
    }
}

bool DoUnHook(ArtMethod *target, ArtMethod *backup,
              const art::dex::ClassDef *hooked_class_def) {
    /* DoUnHook restores the complete ArtMethod body. Keep it inside the same
     * ART suspension boundary in every backend, including Pixel 6 M6. */
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant UnHook", false);
    LOGV("Unhooking: target = %p, backup = %p", target, backup);
#ifdef LSPLANT_M6_BACKEND
    /* M6b DoUnHook: smart_uninstall KPM slot + restore backup entry_point → original OAT VA
     * (so the subsequent CopyFrom propagates the correct VA back to target).
     *
     * smart_uninstall 返回值语义：
     *   0 = full：UXN cleared + KPM slot freed + bridge slot freed；erase m6_hook_slots_ 记录。
     *   1 = partial：同一 OAT 页上仍有其他方法处于 hook 状态，UXN 保留；
     *       KPM fault handler 已把 redirect_va 改为 backup_ep（ART interp bridge），
     *       使 target 执行效果为「已卸钩」但 m6_hook_slots_ 记录保留（Phase C rehook 依赖）。
     *  <0 = error：保留 bridge slot 记录，并让本次 UnHook 继续把 target 切到
     *       backup 的 pass-through 路径；未来 rehook 再把 target.entry_point
     *       恢复到 original OAT VA。
     *
     * Note: target's entry_point was never modified by DoHook (M6b uses PTE.UXN=1
     * instead), so after full uninstall the OAT page becomes executable again and the
     * original entry_point in target is still valid — target resumes normal execution
     * after CopyFrom restores the full ArtMethod body. */
    {
        M6HookRecord record{};
        const bool has_record = ReadM6HookRecord(target, &record);
        if (!has_record) {
            /* hooked_methods_ 仍声明已 hook，但 backend 元数据缺失；任何继续 commit
             * 都可能发布孤儿 slot，故 sticky poison。 */
            PoisonM6Transaction(target, -1);
            LOGE("M6b DoUnHook: no M6 slot record for target");
            return false;
        }
        int32_t  bridge_slot = record.slot_idx;
        uint64_t orig_va     = record.original_oat_va;
        bool     is_fallback = record.is_entry_point_fallback;
        uint64_t shim_va     = record.shim_va;
        if (is_fallback) {
            /* entry_point fallback 卸钩：无 KPM/UXN，无 partial 状态。把 backup
             * entry_point 还原为原 OAT VA（下方 CopyFrom 把它传回 target.entry_point
             * = boot OAT VA，再次可执行），munmap shim 页，erase 记录。 */
            /* EP Spoof 注销：还原 entry_point 前先从 spoof 表移除，
             * 还原后 RASP 再读字段会得到真实 OAT VA，无需再 spoof。 */
            shadowhook_ep_spoof_unregister(
                reinterpret_cast<uintptr_t>(target) + 24);
            backup->SetEntryPoint(reinterpret_cast<void *>(orig_va));
            shadowhook_m6_free_named_shim(reinterpret_cast<void *>(shim_va));
            m6_hook_slots_().erase(target);
        } else if (bridge_slot >= 0) {
            /* backup->GetEntryPoint() = ART interpreter bridge VA（DoHook 时
             * SetEntryPointsToInterpreter(backup) 所写），作为 partial path 的
             * redirect_va（fault handler 在 partial 状态把 regs->pc 改为此值）。 */
            uint64_t backup_ep = reinterpret_cast<uint64_t>(backup->GetEntryPoint());
            int rc = shadowhook_m6_smart_uninstall_for_lsplant(bridge_slot, backup_ep);
            if (rc == 0) {
                /* Full uninstall: UXN cleared, KPM slot freed, bridge slot cleared.
                 * 把 backup entry_point 恢复到原 OAT VA，CopyFrom 会把它传回 target。*/
                backup->SetEntryPoint(reinterpret_cast<void *>(orig_va));
                if (!EraseM6HookRecord(target, bridge_slot)) {
                    /* backend 已清但 stale metadata 会让后续 rehook 使用已释放 slot。 */
                    PoisonM6Transaction(target, bridge_slot);
                    LOGE("M6b DoUnHook: full uninstall metadata erase failed");
                    return false;
                }
            } else if (rc == 1) {
                /* Partial uninstall: 同一 OAT 页上还有其他方法 hook 在位。
                 * KPM slot redirect_va 已改为 backup_ep（interp bridge）；
                 * target 的执行效果为「已卸钩」（UXN trap 重定向到 interp）。
                 * m6_hook_slots_ 记录保留，Phase C 的 is_rehook 检测依赖它。*/
                /* DO NOT erase m6_hook_slots_() — Phase C rehook needs bridge_slot */
                /* spec §6.2: 设 backup entry_point = target OAT VA，使上层
                 * CopyFrom(backup → target) 是 no-op，target.entry_point 保持
                 * OAT VA 不变（M6b 靠 OAT page UXN trap 拦截，不读 entry_point
                 * 字段，但 ART fast dispatch 读它——partial unhook 后 target 仍
                 * 期望走 OAT VA 触发 fault handler，不能变成 interp bridge VA）。*/
                backup->SetEntryPoint(target->GetEntryPoint());
                if (!TransitionM6HookRecord(
                        target, bridge_slot,
                        M6HookRecord::State::kPassThrough)) {
                    PoisonM6Transaction(target, bridge_slot);
                    LOGE("M6b DoUnHook: pass-through metadata publish failed");
                    return false;
                }
            } else {
                LOGE("M6b DoUnHook: smart_uninstall(bridge=%d) failed rc=%d;"
                     " PTE.UXN may still be armed — target SIGSEGV risk.",
                     bridge_slot, rc);
                if (!TransitionM6HookRecord(
                        target, bridge_slot,
                        M6HookRecord::State::kPassThrough)) {
                    /* metadata 若不能可靠切到 pass-through，后续 rehook/ARM_PAGES
                     * 都失去一致性保证，只能 sticky poison fail-closed。 */
                    PoisonM6Transaction(target, bridge_slot);
                    LOGE("M6b DoUnHook: rc<0 pass-through metadata publish failed");
                    return false;
                }
                /* 保留 m6_hook_slots_ 记录（不 erase），使 bridge_slot 引用不丢失。
                 * backup.entry_point 保持当前值：
                 *   - Java 方法：DoHook 时已改成 interpreter bridge；
                 *   - native 方法：保持 JNI/original bridge。
                 * 函数尾部的 CopyFrom 会把 target 切到该 pass-through 路径，因此
                 * 本次 UnHook 的用户态可见效果仍然是“已卸钩”。
                 *
                 * 未来同 target 再次 DoHook 时，rehook 路径（Step 0）会找到此
                 * kPassThrough 记录，更新 redirect_va，并把 target.entry_point
                 * 显式恢复到 original OAT VA。 */
            }
        } else {
            PoisonM6Transaction(target, bridge_slot);
            LOGE("M6b DoUnHook: invalid M6 slot state");
            return false;
        }
    }
#elif defined(LSPLANT_SKIP_ENTRY_POINT_PATCH)
    /* [M4b.3 R1+R2 P1 修] 拆 hook (PTE 主路径 / Dobby fallback) + 还原 target.entry_point。
     *
     * 顺序：
     *   1. 查 pte_hook_slots_(target) 拿 (slot_idx, original_oat_va)
     *   2. PTE 路径：shadowhook_pte_uninstall_for_lsplant 拆 KPM slot + 释放 ghost 页
     *               Dobby 路径：DobbyDestroy 拆 inline patch (target_va_for_dobby=original_oat_va)
     *   3. **关键 [R2 P1-C 修]**：把 backup.entry_point 改回 original_oat_va，让接下来
     *      CopyFrom 把"原始 .oat VA"灌回 target，而不是悬空的 ghost VA（已 free）.
     *   4. CopyFrom 由上游既有 lsplant 逻辑做：把整个 backup（含修正后的 entry_point）拷回 target.
     *   5. 上游 CopyFrom 后调 SetAccessFlags 还原 access_flags. */
    int slot_for_target = SHADOWHOOK_SLOT_INVALID;
    uint64_t original_oat_va = 0;
    pte_hook_slots_().if_contains(target, [&slot_for_target, &original_oat_va](const auto &it) {
        slot_for_target = it.second.slot_idx;
        original_oat_va = it.second.original_oat_va;
    });
    if (slot_for_target >= 0 || slot_for_target == SHADOWHOOK_SLOT_FALLBACK_DOBBY) {
        /* M4b-Polish I3 (codex T1 round 4 P2): rc==-EBUSY (-16) 通常是 transient (并发 install 在
         * Step 5 短暂 reserved=true 扫 used slot 时撞上). 重试 4 次 (yield via sched_yield)
         * 再认 stuck. install Step 5 hold reserved 仅 ~10 instr，4 次让出 CPU 足以解锁. */
        long rc = 0;
        for (int retry = 0; retry < 4; retry++) {
            rc = shadowhook_pte_uninstall_for_lsplant(
                     slot_for_target,
                     reinterpret_cast<void *>(original_oat_va));
            if (rc != -16 /* -EBUSY */) break;
            sched_yield();
        }
        if (rc != 0) {
            LOGE("DoUnHook backend restore failed slot=%d rc=%ld; preserving hook record for retry",
                 slot_for_target, rc);
            return false;
        }
        /* [R2 P1-C 修] 还原 backup.entry_point → original_oat_va：
         * - PTE 路径：pte_backup ghost VA 可能已被 uninstall 释放（成功路径）或仍在（失败路径）
         * - Dobby 路径：origin 指向 Dobby 跳板内 backup 区，DobbyDestroy 拆后跳板可能被释放
         * - 统一改回 original_oat_va 最安全（成功路径下 .oat PTE 已 restore UXN=0，正常可执行；
         *   失败路径下虽然不"最佳"但比悬空指针好）.
         * call_original 之后用 backup 调用：原 .oat 段（成功路径 PTE restore UXN=0）安全可执行. */
        backup->SetEntryPoint(reinterpret_cast<void *>(original_oat_va));
        pte_hook_slots_().erase(target);
    } else {
        LOGE("DoUnHook: no PTE/Dobby slot record for target");
        return false;
    }
#endif
    auto access_flags = target->GetAccessFlags();
    target->CopyFrom(backup);
    target->SetAccessFlags(access_flags);
    /* Retire target/backup/class bookkeeping before mutators resume.  A
     * physical restore failure returns above and deliberately keeps every
     * record published for a later retry. */
    ForgetHookedRecord(target, hooked_class_def, backup);
    LOGV("Done unhook: target(%p:0x%x) -> %p; backup(%p:0x%x) -> %p;", target,
         target->GetAccessFlags(), target->GetEntryPoint(), backup, backup->GetAccessFlags(),
         backup->GetEntryPoint());
    return true;
}

std::string GetProxyMethodShorty(JNIEnv *env, jobject proxy_method) {
    const auto return_type = JNI_CallObjectMethod(env, proxy_method, method_get_return_type);
    const auto parameter_types =
        JNI_Cast<jobjectArray>(JNI_CallObjectMethod(env, proxy_method, method_get_parameter_types));
    auto integer_class = JNI_FindClass(env, "java/lang/Integer");
    auto long_class = JNI_FindClass(env, "java/lang/Long");
    auto float_class = JNI_FindClass(env, "java/lang/Float");
    auto double_class = JNI_FindClass(env, "java/lang/Double");
    auto boolean_class = JNI_FindClass(env, "java/lang/Boolean");
    auto byte_class = JNI_FindClass(env, "java/lang/Byte");
    auto char_class = JNI_FindClass(env, "java/lang/Character");
    auto short_class = JNI_FindClass(env, "java/lang/Short");
    auto void_class = JNI_FindClass(env, "java/lang/Void");
    static auto *kIntTypeField =
        JNI_GetStaticFieldID(env, integer_class, "TYPE", "Ljava/lang/Class;");
    static auto *kLongTypeField =
        JNI_GetStaticFieldID(env, long_class, "TYPE", "Ljava/lang/Class;");
    static auto *kFloatTypeField =
        JNI_GetStaticFieldID(env, float_class, "TYPE", "Ljava/lang/Class;");
    static auto *kDoubleTypeField =
        JNI_GetStaticFieldID(env, double_class, "TYPE", "Ljava/lang/Class;");
    static auto *kBooleanTypeField =
        JNI_GetStaticFieldID(env, boolean_class, "TYPE", "Ljava/lang/Class;");
    static auto *kByteTypeField =
        JNI_GetStaticFieldID(env, byte_class, "TYPE", "Ljava/lang/Class;");
    static auto *kCharTypeField =
        JNI_GetStaticFieldID(env, char_class, "TYPE", "Ljava/lang/Class;");
    static auto *kShortTypeField =
        JNI_GetStaticFieldID(env, short_class, "TYPE", "Ljava/lang/Class;");
    static auto *kVoidTypeField =
        JNI_GetStaticFieldID(env, void_class, "TYPE", "Ljava/lang/Class;");

    auto int_type = JNI_GetStaticObjectField(env, integer_class, kIntTypeField);
    auto long_type = JNI_GetStaticObjectField(env, long_class, kLongTypeField);
    auto float_type = JNI_GetStaticObjectField(env, float_class, kFloatTypeField);
    auto double_type = JNI_GetStaticObjectField(env, double_class, kDoubleTypeField);
    auto boolean_type = JNI_GetStaticObjectField(env, boolean_class, kBooleanTypeField);
    auto byte_type = JNI_GetStaticObjectField(env, byte_class, kByteTypeField);
    auto char_type = JNI_GetStaticObjectField(env, char_class, kCharTypeField);
    auto short_type = JNI_GetStaticObjectField(env, short_class, kShortTypeField);
    auto void_type = JNI_GetStaticObjectField(env, void_class, kVoidTypeField);

    std::string out;
    auto type_to_shorty = [&](const ScopedLocalRef<jobject> &type) {
        if (JNI_IsSameObject(env, type, int_type)) return 'I';
        if (JNI_IsSameObject(env, type, long_type)) return 'J';
        if (JNI_IsSameObject(env, type, float_type)) return 'F';
        if (JNI_IsSameObject(env, type, double_type)) return 'D';
        if (JNI_IsSameObject(env, type, boolean_type)) return 'Z';
        if (JNI_IsSameObject(env, type, byte_type)) return 'B';
        if (JNI_IsSameObject(env, type, char_type)) return 'C';
        if (JNI_IsSameObject(env, type, short_type)) return 'S';
        if (JNI_IsSameObject(env, type, void_type)) return 'V';
        return 'L';
    };
    out += type_to_shorty(return_type);
    for (const auto &param : parameter_types) {
        out += type_to_shorty(param);
    }
    return out;
}
}  // namespace

inline namespace v2 {
extern "C++" {

using ::lsplant::IsHooked;

[[maybe_unused]] bool Init(JNIEnv *env, const InitInfo &info) {
    if (!info.inline_hooker || !info.inline_unhooker || !info.art_symbol_resolver ||
        !info.art_symbol_prefix_resolver) {
        return false;
    }
    bool static kInit = InitConfig(info) && InitJNI(env)
#ifndef LSPLANT_M6_BACKEND
        /* InitNative installs ~35 Dobby inline hooks on libart functions
         * (FixupStaticTrampolines, ClassLinker::InitializeClass, etc.).
         * The retired M6 source configuration skips those inline hooks and
         * initializes only the symbol-resolved suspension subset below. */
        && InitNative(env, info)
#else
        /* M6b: call only the Dobby-free subset needed for DoHook.
         * ArtMethod::Init sets art_method_field + access_flags_offset (no
         * Dobby hooks on API 33). ScopedSuspendAll/Thread/GC helpers are
         * symbol-only resolvers, and ClassLinker::InitM6b resolves only the
         * interpreter bridge entry point. */
        && InitNativeM6b(env, info)
#endif  /* LSPLANT_M6_BACKEND */
        ;
    return kInit;
}

[[maybe_unused]] bool M6TransactionHealthy() {
#ifdef LSPLANT_M6_BACKEND
    return g_m6_transaction_healthy.load(std::memory_order_acquire);
#else
    return true;
#endif
}

[[maybe_unused]] bool M6CommitWithSuspendedThreads(
        const std::function<bool()> &commit) {
    if (!commit) return false;
#ifdef LSPLANT_M6_BACKEND
    if (!M6TransactionHealthy()) return false;
    auto *self = Thread::Current();
    if (!self) return false;
    ScopedGCCriticalSection section(
        self, art::gc::kGcCauseDebugger, art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant M6 commit", false);
    return M6TransactionHealthy() && commit();
#else
    return commit();
#endif
}

/* Moving-GC guard（Pine/Tine 修法移植，专用守卫线程版）。
 *
 * 克隆式 ART hook 的 backup ArtMethod 是 GC 盲区：裸 operator new 内存、不挂类方法
 * 数组、不在栈上，其 declaring_class（32 位压缩 GcRoot）不被移动 GC 就地修正；
 * CC/CMC 压缩后调原方法（Method.invoke → EnsureInitialized → PrettyClass/GetDescriptor）
 * 读野 Class* 即 SIGSEGV（Pine/Tine 实机事故；LSPlant backup 同为裸克隆，风险同构）。
 *
 * 修复：存在活 hook 期间持 disable-moving-gc 计数（只禁移动、不停回收）。
 * 直取 Heap::IncrementDisableMovingGC 需要 Heap*——Pixel6/A13 的 libart 把
 * Runtime::GetHeap inline 掉了（dynsym 无此符号），故用公共 JNI 路径：ART 的
 * GetPrimitiveArrayCritical 内部正是 Heap::IncrementDisableMovingGC（同一计数器、
 * 可重入、调用时等在途移动 GC 完成），对一个全局 dummy byte[] 持 critical 区间
 * 即达到同一语义，零私有符号/偏移依赖。
 *
 * 关键架构约束（Pixel6/A13 真机实测）：ART 硬性规定 GetPrimitiveArrayCritical 后
 * 同一线程不得再调其它 JNI（否则 fatal「using JNI after critical get」SIGABRT）。
 * 因此 critical 由**专用守卫线程**持有：Heap 的 disable-moving-gc 计数是进程
 * 全局的，哪条线程持锁不影响 GC 语义；业务线程（含 hook 安装线程）的 JNI 使用
 * 不受限。守卫线程 AttachCurrentThread 后只做：建 dummy → GetPrimitiveArrayCritical
 * → 等待请求 → ReleasePrimitiveArrayCritical（配对调用合法）。计数 0↔1 转换才与
 * 守卫线程握手（condvar 同步完成），中间 acquire/release 纯计数。任一步失败 →
 * 降级 no-op（与改动前行为一致，零回归）。 */
static std::mutex g_mgc_mutex;
static std::condition_variable g_mgc_cv;
static size_t g_mgc_count = 0;
static bool g_mgc_thread_started = false;
static bool g_mgc_thread_failed = false;
static int g_mgc_request = 0;    /* 0=无 1=acquire 2=release */
static int g_mgc_done = 0;       /* 握手回传：1=ok -1=fail */
static jbyteArray g_mgc_dummy = nullptr;
static jbyte *g_mgc_elements = nullptr;
static bool g_mgc_logged = false;

static void MovingGcGuardThreadMain(JavaVM *vm) {
    JNIEnv *env = nullptr;
    if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK || !env) {
        std::lock_guard lk(g_mgc_mutex);
        g_mgc_thread_failed = true;
        g_mgc_done = -1;
        g_mgc_cv.notify_all();
        return;
    }

    /* 建 dummy（持 critical 前的普通 JNI 窗口内完成） */
    {
        jbyteArray local = env->NewByteArray(1);
        if (local) {
            g_mgc_dummy = (jbyteArray)env->NewGlobalRef(local);
            env->DeleteLocalRef(local);
        }
        if (env->ExceptionCheck()) env->ExceptionClear();
    }

    std::unique_lock lk(g_mgc_mutex);
    while (true) {
        g_mgc_cv.wait(lk, [] { return g_mgc_request != 0; });
        int req = g_mgc_request;
        g_mgc_request = 0;
        if (req == 1) {
            if (g_mgc_dummy && !g_mgc_elements) {
                g_mgc_elements = (jbyte *)env->GetPrimitiveArrayCritical(g_mgc_dummy, nullptr);
            }
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                g_mgc_elements = nullptr;
            }
            g_mgc_done = g_mgc_elements ? 1 : -1;
        } else if (req == 2) {
            if (g_mgc_elements && g_mgc_dummy) {
                env->ReleasePrimitiveArrayCritical(g_mgc_dummy, g_mgc_elements, JNI_ABORT);
                g_mgc_done = 1;
            } else {
                g_mgc_done = -1;
            }
            g_mgc_elements = nullptr;
        }
        lk.unlock();
        g_mgc_cv.notify_all();
        lk.lock();
    }
}

static void *MovingGcGuardThreadEntry(void *arg) {
    MovingGcGuardThreadMain((JavaVM *)arg);
    return nullptr;
}

static void MovingGcGuardAcquire(JNIEnv *env) {
    std::unique_lock lk(g_mgc_mutex);
    if (g_mgc_count++ != 0) return;

    if (!g_mgc_thread_started && !g_mgc_thread_failed) {
        JavaVM *vm = nullptr;
        if (env && env->GetJavaVM(&vm) == JNI_OK && vm) {
            pthread_t th;
            if (pthread_create(&th, nullptr, MovingGcGuardThreadEntry, vm) == 0) {
                pthread_detach(th);
                g_mgc_thread_started = true;
            } else {
                g_mgc_thread_failed = true;
            }
        } else {
            g_mgc_thread_failed = true;
        }
    }

    if (g_mgc_thread_failed) {
        if (!g_mgc_logged) {
            LOGW("moving-gc guard unavailable (guard thread); backup declaring_class unprotected");
            g_mgc_logged = true;
        }
        return;
    }

    g_mgc_done = 0;
    g_mgc_request = 1;
    g_mgc_cv.notify_all();
    g_mgc_cv.wait(lk, [] { return g_mgc_done != 0; });
    if (g_mgc_done != 1 && !g_mgc_logged) {
        LOGW("moving-gc guard unavailable; backup declaring_class unprotected");
        g_mgc_logged = true;
    }
}

static void MovingGcGuardRelease(JNIEnv *env) {
    std::unique_lock lk(g_mgc_mutex);
    if (g_mgc_count == 0 || --g_mgc_count != 0) return;
    if (!g_mgc_thread_started || g_mgc_thread_failed) return;
    (void)env;
    g_mgc_done = 0;
    g_mgc_request = 2;
    g_mgc_cv.notify_all();
    g_mgc_cv.wait(lk, [] { return g_mgc_done != 0; });
}

static jobject HookImpl(
    JNIEnv *env, jobject target_method, jobject hooker_object,
    jobject callback_method,
    const std::function<bool(jobject)> *backup_publisher) {
#ifdef LSPLANT_M6_BACKEND
    if (!M6TransactionHealthy()) {
        LOGE("M6 Hook rejected: transaction poisoned; process restart required");
        return nullptr;
    }
#endif
    if (!target_method || !JNI_IsInstanceOf(env, target_method, executable)) {
        LOGE("target method is not an executable");
        return nullptr;
    }
    if (!callback_method || !JNI_IsInstanceOf(env, callback_method, executable)) {
        LOGE("callback method is not an executable");
        return nullptr;
    }

    jmethodID hook_method = nullptr;
    jmethodID backup_method = nullptr;
    jfieldID hooker_field = nullptr;

    auto target_class =
        JNI_Cast<jclass>(JNI_CallObjectMethod(env, target_method, method_get_declaring_class));
    constexpr static uint32_t kAccClassIsProxy = 0x00040000;
    bool is_proxy = JNI_GetIntField(env, target_class, class_access_flags) & kAccClassIsProxy;
    auto *target = ArtMethod::FromReflectedMethod(env, target_method);
    bool is_static = target->IsStatic();
    std::lock_guard transaction_guard(HookTransactionMutex());

    if (IsHooked(target, true)) {
        LOGW("Skip duplicate hook");
        return nullptr;
    }

    ScopedLocalRef<jclass> built_class{env};
    {
        auto callback_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, callback_method, method_get_name));
        JUTFString callback_method_name(callback_name);
        auto target_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, target_method, method_get_name));
        JUTFString target_method_name(target_name);
        auto callback_class = JNI_Cast<jclass>(
            JNI_CallObjectMethod(env, callback_method, method_get_declaring_class));
        auto callback_class_loader =
            JNI_CallObjectMethod(env, callback_class, class_get_class_loader);
        auto callback_class_name =
            JNI_Cast<jstring>(JNI_CallObjectMethod(env, callback_class, class_get_name));
        JUTFString class_name(callback_class_name);
        if (!JNI_IsInstanceOf(env, hooker_object, callback_class)) {
            LOGE("callback_method is not a method of hooker_object");
            return nullptr;
        }
        std::tie(built_class, hooker_field, hook_method, backup_method) = WrapScope(
            env,
            BuildDex(env, callback_class_loader.get(),
                     __builtin_expect(is_proxy, 0) ? GetProxyMethodShorty(env, target_method)
                                                   : ArtMethod::GetMethodShorty(env, target_method),
                     is_static, target->IsConstructor() ? "constructor" : target_method_name.get(),
                     class_name.get(), callback_method_name.get()));
        if (!built_class || !hooker_field || !hook_method || !backup_method) {
            LOGE("Failed to generate hooker");
            return nullptr;
        }
    }

    auto reflected_hook = JNI_ToReflectedMethod(env, built_class, hook_method, is_static);
    auto reflected_backup = JNI_ToReflectedMethod(env, built_class, backup_method, is_static);

    JNI_CallVoidMethod(env, reflected_backup, set_accessible, JNI_TRUE);

    auto *hook = ArtMethod::FromReflectedMethod(env, reflected_hook.get());
    auto *backup = ArtMethod::FromReflectedMethod(env, reflected_backup.get());

    JNI_SetStaticObjectField(env, built_class, hooker_field, hooker_object);

    // shadowhook: 在 DoHook 之前（backup 未被 BackupTo 污染时）取 backup 的 jmethodID。
    // DoHook 内部 BackupTo(backup) 会把 target 的 DexMethodIndex 复制进 backup，之后对
    // backup 调用 env->FromReflectedMethod 在 opaque jni ids 模式下会崩（EncodeGenericId
    // 用错误的 DexMethodIndex 计算 index）。此处预先取好并存入 hooked_methods_，供 UnHook
    // kInternalMethods 传播安全使用。
    // 注：backup_method（JNI_GetMethodID 取的）在 pointer-id 模式下 == (jmethodID)ArtMethod*，
    // 在 opaque-id 模式下是合法的 opaque index——两种模式均安全。
    jmethodID backup_jmethodid = backup_method;
    jmethodID target_jmethodid = env->FromReflectedMethod(target_method);
    jobject global_backup = JNI_NewGlobalRef(env, reflected_backup);
    if (!global_backup) {
        LOGE("Failed to retain reflected backup");
        return nullptr;
    }

    /* A native plugin cannot safely publish the backup after Hook() returns:
     * the normal Dobby backend is already live at that point, so another
     * mutator may enter the callback first. Give the bridge the fully created
     * backup while target is still untouched. A rejected publication leaves
     * no hook or LSPlant bookkeeping behind. */
    bool backup_published = false;
    if (backup_publisher) {
        bool accepted = false;
        try {
            accepted = (*backup_publisher)(global_backup);
        } catch (...) {
            /* Treat an escaping C++ publisher exactly like any other rejected
             * publication, including its mandatory NULL rollback. */
            LOGE("Backup publisher threw while publishing hook");
        }
        if (!accepted || env->ExceptionCheck()) {
            RollbackBackupPublication(env, *backup_publisher);
            env->DeleteGlobalRef(global_backup);
            LOGE("Backup publisher rejected hook or left a pending exception");
            return nullptr;
        }
        backup_published = true;
    }

    const art::dex::ClassDef *hooked_class_def = nullptr;
    const art::dex::ClassDef *deoptimized_class_def = nullptr;
#ifndef LSPLANT_M6_BACKEND
    hooked_class_def = target->GetDeclaringClass()->GetClassDef();
    deoptimized_class_def = hook->GetDeclaringClass()->GetClassDef();
#endif
    bool hook_recorded = false;
    bool installed = false;
    /* backup 是裸克隆 ArtMethod，declaring_class 不被移动 GC 跟踪；必须在 DoHook
     * （BackupTo 产生裸克隆 + hook 生效、其他 ART 线程恢复运行）之前就禁移动 GC。
     * 旧实现在成功后才 acquire——DoHook→acquire 窗口内移动 GC 仍可踩 backup 的
     * declaring_class 野指针。配对：成功路径保持持有（UnHook 时 release）；
     * 失败路径在下方 cleanup 统一 release。
     * （2026-08-16 真机验证：此前位置被怀疑导致 hook=0，A/B 回退后证明真凶是
     * javavis controller 的 V2 memfd 注入 vs System.load 双实例；本位置经
     * m52g31 + javavis 双 PASS 复核无回归。） */
    MovingGcGuardAcquire(env);
    try {
        installed = DoHook(
            target, hook, backup, hooked_class_def,
            deoptimized_class_def, is_proxy, global_backup,
            backup_jmethodid, target_jmethodid, &hook_recorded);
    } catch (...) {
        /* No C++ exception may cross JNI/plugin ABI. On the supported Dobby
         * path every potentially throwing allocation occurs before target
         * activation, and DoHook's record guard restores pre-commit state. */
        LOGE("Unexpected exception while installing hook");
        installed = false;
    }
    if (installed) {
        /* MovingGcGuard 已在 DoHook 前 acquire（见上方），活 hook 期间保持持有，
         * UnHook 成功路径对称 release。 */
        std::apply(
            [backup_method, target_jmethodid](auto... v) {
                ((*v == target_jmethodid &&
                  (LOGD("Propagate internal used method because of hook"), *v = backup_method)) ||
                 ...);
            },
            kInternalMethods);
        return global_backup;
    }

    /* An uncertain M6 rollback cannot cross this call boundary: the publisher
     * callback may capture caller-owned opaque state whose lifetime ends when
     * HookWithBackupPublisher returns. */
#ifdef LSPLANT_M6_BACKEND
    if (hook_recorded && !M6TransactionHealthy()) {
        /* The backend may still dispatch this callback.  Keep the publisher's
         * non-null backup visible together with hooked_methods_ and its
         * GlobalRef while the publisher callback and its opaque capture are
         * still alive on this stack.  A publisher is not required to outlive
         * HookWithBackupPublisher(), so returning an ambiguous live hook would
         * immediately make any later rollback callback unsafe to invoke. */
        bool restored = false;
        for (int retry = 0; retry < 4 && !restored; ++retry) {
            restored = DoUnHook(target, backup, hooked_class_def);
            if (!restored) sched_yield();
        }
        if (!restored) {
            /* Neither clearing the published backup nor returning to a caller
             * that may destroy its opaque state is safe.  Stop the process
             * while every retained object is still valid. */
            LOGE("M6 hook rollback remained ambiguous after retries");
            std::abort();
        }
        /* DoUnHook removed the complete LSPlant record.  The ordinary cleanup
         * below may now withdraw the publication and release this local
         * transaction's GlobalRef.  The sticky health gate intentionally
         * remains false, preventing another M6 transaction in this process. */
        hook_recorded = false;
    }
#endif
    if (hook_recorded) {
        ForgetHookedRecord(target, hooked_class_def, backup);
    }
    if (backup_published) {
        RollbackBackupPublication(env, *backup_publisher);
    }
    /* 失败路径：与 DoHook 前的 MovingGcGuardAcquire 对称释放（成功路径在 UnHook 才释放）。 */
    MovingGcGuardRelease(env);
    env->DeleteGlobalRef(global_backup);
    return nullptr;
}

[[maybe_unused]] jobject Hook(JNIEnv *env, jobject target_method,
                              jobject hooker_object, jobject callback_method) {
    return HookImpl(env, target_method, hooker_object, callback_method, nullptr);
}

[[maybe_unused]] jobject HookWithBackupPublisher(
    JNIEnv *env, jobject target_method, jobject hooker_object,
    jobject callback_method,
    const std::function<bool(jobject)> &publish_backup) {
    return HookImpl(env, target_method, hooker_object, callback_method,
                    &publish_backup);
}

[[maybe_unused]] bool UnHook(JNIEnv *env, jobject target_method) {
    if (!target_method || !JNI_IsInstanceOf(env, target_method, executable)) {
        LOGE("target method is not an executable");
        return false;
    }
    auto *target = ArtMethod::FromReflectedMethod(env, target_method);
    std::lock_guard transaction_guard(HookTransactionMutex());
    jobject reflected_backup = nullptr;
    art::ArtMethod *backup = nullptr;
    jmethodID backup_jmethodid = nullptr;
    jmethodID target_jmethodid = nullptr;
    hooked_methods_().if_contains(
        target, [&reflected_backup, &backup, &backup_jmethodid,
                 &target_jmethodid](const auto &it) {
            std::tie(reflected_backup, backup, backup_jmethodid,
                     target_jmethodid) = it.second;
        });
    if (!reflected_backup || !backup) {
        LOGE("Unable to unhook a method that is not hooked");
        return false;
    }
    // shadowhook 修（V2）: Android 13+ opaque jni ids 下的 UnHook SIGSEGV 根因与修复。
    //
    // 【根因】env->FromReflectedMethod(reflected_backup) 在 DoHook 之后调用会崩：
    //   DoHook → BackupTo(backup) 把 target 的 DexMethodIndex 等字段复制进了 backup 的
    //   ArtMethod 内存。随后 ART 的 JniIdManager::EncodeGenericId 按 backup 里的
    //   DexMethodIndex 查 target 方法的 opaque index，因 target 和 backup 指向同一 index
    //   导致重复注册/越界——SIGSEGV at _JNIEnv::FromReflectedMethod+36。
    //
    // 【V1 不完整】仅用 reinterpret_cast<jmethodID>(backup) 绕过崩溃，但在 opaque-id 模式下
    //   该值不等于 kInternalMethods 里存的 opaque backup jmethodID（V1 注释分析是正确的——
    //   kInternalMethods 里的值由 JNI_GetMethodID 产生的 opaque index，而 V1 用的是
    //   ArtMethod* 强转，两者不同，导致 kInternalMethods 恢复传播永不命中）。
    //
    // 【V2 完整修复】在 Hook 时 DoHook 之前（backup 还是干净的 DexBuilder 方法，BackupTo 还
    //   未执行）预先取 backup_jmethodid = backup_method（JNI_GetMethodID 取的值，pointer-id
    //   模式下是 ArtMethod*，opaque-id 模式下是合法 opaque index），存入 hooked_methods_
    //   tuple 第三字段。UnHook 时直接用这个预存值，完全不调用 env->FromReflectedMethod。
    //
    // target_method_id 继续用 env->FromReflectedMethod(target_method)：target_method 是真实
    // 的 Java 方法（非 BackupTo 合成品），opaque-id 模式下返回合法 opaque index，写入
    // kInternalMethods 后 JNI_Call*Method 可正常使用。不能用 ArtMethod* 强转代替，
    // 因为 opaque-id 模式下 JNI 调用不接受指针值作为 jmethodID。
    /* Keep every map/set entry and the GlobalRef intact until the physical
     * restore succeeds.  A failed PTE/inline uninstall is therefore retryable
     * instead of being reported as logically unhooked. */
    const art::dex::ClassDef *hooked_class_def = nullptr;
#ifndef LSPLANT_M6_BACKEND
    hooked_class_def = target->GetDeclaringClass()->GetClassDef();
#endif
    if (!DoUnHook(target, backup, hooked_class_def)) {
        return false;
    }
    /* 与 HookImpl 成功路径的 MovingGcGuardAcquire() 对称：卸钩后 backup 不再被调用。 */
    MovingGcGuardRelease(env);
    std::apply(
        [backup_jmethodid, target_jmethodid](auto... v) {
            ((*v == backup_jmethodid &&
              (LOGD("Propagate internal used method because of unhook"),
               *v = target_jmethodid)) ||
             ...);
        },
        kInternalMethods);

    backuped_proxy_methods_().erase(backup);
#ifndef LSPLANT_M6_BACKEND
    env->DeleteGlobalRef(reflected_backup);
#else
    /* M6 callbacks can still be in-flight after logical UnHook.  Keep the
     * reflected backup GlobalRef valid until ART tears down the process. */
    (void)reflected_backup;
#endif
    return true;
}

[[maybe_unused]] bool IsHooked(JNIEnv *env, jobject method) {
    if (!method || !JNI_IsInstanceOf(env, method, executable)) {
        LOGE("method is not an executable");
        return false;
    }
    auto *art_method = ArtMethod::FromReflectedMethod(env, method);
    return IsHooked(art_method);
}

[[maybe_unused]] bool Deoptimize(JNIEnv *env, jobject method) {
    if (!method || !JNI_IsInstanceOf(env, method, executable)) {
        LOGE("method is not an executable");
        return false;
    }
    auto *art_method = ArtMethod::FromReflectedMethod(env, method);
    std::lock_guard transaction_guard(HookTransactionMutex());
    // record the original but not the backup
#ifndef LSPLANT_M6_BACKEND
    RecordDeoptimized(art_method->GetDeclaringClass()->GetClassDef(), art_method);
#endif  /* LSPLANT_M6_BACKEND */
    if (auto *backup = IsHooked(art_method); backup) {
        art_method = backup;
    }
    if (!art_method || art_method->IsNative()) {
        return false;
    }
    return ClassLinker::SetEntryPointsToInterpreter(art_method);
}

[[maybe_unused]] void *GetNativeFunction(JNIEnv *env, jobject method) {
    if (!method || !JNI_IsInstanceOf(env, method, executable)) {
        LOGE("method is not an executable");
        return nullptr;
    }
    auto *art_method = ArtMethod::FromReflectedMethod(env, method);
    if (!art_method->IsNative()) {
        LOGE("method is not native");
        return nullptr;
    }
    return art_method->GetData();
}

[[maybe_unused]] bool MakeClassInheritable(JNIEnv *env, jclass target) {
    if (!target) {
        LOGE("target class is null");
        return false;
    }
    const auto constructors =
        JNI_Cast<jobjectArray>(JNI_CallObjectMethod(env, target, class_get_declared_constructors));
    auto access_flags = JNI_GetIntField(env, target, class_access_flags);
    constexpr static jint kAccFinal = 0x0010;
    JNI_SetIntField(env, target, class_access_flags, access_flags & ~kAccFinal);
    for (const auto &constructor : constructors) {
        auto *method = ArtMethod::FromReflectedMethod(env, constructor.get());
        if (method && !method->IsPublic() && !method->IsProtected()) method->SetProtected();
        if (method && method->IsFinal()) method->SetNonFinal();
    }
    return true;
}

[[maybe_unused]] bool MakeDexFileTrusted(JNIEnv *env, jobject cookie) {
    JavaDebuggableGuard guard;
    if (!cookie) return false;
    return DexFile::SetTrusted(env, cookie);
}

bool UnHookAll(JNIEnv *env) {
    std::lock_guard transaction_guard(HookTransactionMutex());
    // L1 Critical fix: 原实现收集 std::get<0>(kv.second) = reflected_backup（backup 的
    // jobject GlobalRef），传给 UnHook(env, reflected_backup)。UnHook 内部
    // FromReflectedMethod(reflected_backup) 得到 backup 的 ArtMethod*，命中辅助条目
    // （reflected_backup=nullptr）→ erase_if 返回 false → 每次 unhook 静默失败
    // = UnHookAll 完整 no-op。M6 Unload Safety 被 KPM 层独立清理掩盖。
    //
    // Collect primary target keys. Each entry stays published until DoUnHook
    // succeeds; failed entries and GlobalRefs remain intact for retry.
    //
    // LFD-1 的 for_each（phmap submap SharedLock 安全遍历）保留；snapshot ArtMethod*
    // 到本地 vector 后释放锁，再逐个做 erase_if（UniqueLock），避免 self-deadlock。
    std::vector<art::ArtMethod*> targets;
    try {
        hooked_methods_().for_each([&targets](const auto &kv) {
            if (std::get<0>(kv.second) != nullptr) {
                targets.push_back(kv.first);
            }
        });
    } catch (const std::bad_alloc &) {
        LOGE("UnHookAll snapshot allocation failed");
        return false;
    }
    bool all_ok = true;
    for (auto *target : targets) {
        jobject reflected_backup = nullptr;
        art::ArtMethod *backup = nullptr;
        jmethodID backup_jmethodid = nullptr;
        jmethodID target_jmethodid = nullptr;
        hooked_methods_().if_contains(
            target, [&reflected_backup, &backup, &backup_jmethodid,
                     &target_jmethodid](const auto &it) {
                std::tie(reflected_backup, backup, backup_jmethodid,
                         target_jmethodid) = it.second;
            });
        if (!reflected_backup || !backup) {
            continue;
        }
        const art::dex::ClassDef *hooked_class_def = nullptr;
#ifndef LSPLANT_M6_BACKEND
        hooked_class_def = target->GetDeclaringClass()->GetClassDef();
#endif
        if (!DoUnHook(target, backup, hooked_class_def)) {
            all_ok = false;
            continue;
        }

        std::apply(
            [backup_jmethodid, target_jmethodid](auto... v) {
                ((*v == backup_jmethodid &&
                  (LOGD("Propagate internal used method because of unhook-all"),
                   *v = target_jmethodid)) ||
                 ...);
            },
            kInternalMethods);

        backuped_proxy_methods_().erase(backup);
#ifndef LSPLANT_M6_BACKEND
        env->DeleteGlobalRef(reflected_backup);
#else
        /* Same lifetime rule as single UnHook: runtime release is unprovable. */
        (void)reflected_backup;
#endif
    }
    return all_ok;
}
}  // extern "C++"
}  // namespace v2

}  // namespace lsplant
