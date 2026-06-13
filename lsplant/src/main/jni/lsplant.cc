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
/* M6b: DoHook installs an M6 PTE/UXN slot; DoUnHook uninstalls it.
 * Implemented in bridge/lsplant_glue.cpp (C linkage wrappers over sh_m6_*).
 * install: target_oat_va = ArtMethod entry_point VA; trampoline_va = shellcode VA;
 *          *slot_out ≥0 = success.  Returns 0 on success.
 * uninstall: slot_idx ≥0.  Returns 0 on success. */
extern "C" int shadowhook_m6_install_for_lsplant(void *target_oat_va,
                                                   void *trampoline_va,
                                                   int32_t *slot_out);
extern "C" int shadowhook_m6_uninstall_for_lsplant(int32_t slot_idx);
#endif  /* LSPLANT_M6_BACKEND */

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
    if (!ArtMethod::Init(env, handler)) {
        LOGE("M6b: Failed to init ArtMethod");
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

bool DoHook(ArtMethod *target, ArtMethod *hook, ArtMethod *backup) {
#ifndef LSPLANT_M6_BACKEND
    /* ScopedSuspendAll/ScopedGCCriticalSection are initialized by InitNative
     * (via ScopedSuspendAll::Init). M6b skips InitNative (no Dobby on libart),
     * so these objects cannot be constructed.  M6b uses direct KPM PTE/UXN
     * install which does not require ART suspension. */
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant Hook", false);
#endif  /* LSPLANT_M6_BACKEND */
    LOGV("Hooking: target = %s(%p), hook = %s(%p), backup = %s(%p)", target->PrettyMethod().c_str(),
         target, hook->PrettyMethod().c_str(), hook, backup->PrettyMethod().c_str(), backup);

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

        /* Step 1: 捕获原始 OAT entry_point。
         * BackupTo() 已在上方执行，但它只改写 backup 的字段（CopyFrom）和 target 的
         * access_flags（SetNonCompilable / ClearFastInterpretFlag），不触碰 target 的
         * entry_point 字段，所以此处读到的仍是原始 OAT VA。 */
        uint64_t target_oat_va = reinterpret_cast<uint64_t>(target->GetEntryPoint());

        /* Step 2: 安装 M6 PTE/UXN hook */
        int32_t m6_slot = -1;
        int m6_rc = shadowhook_m6_install_for_lsplant(
            reinterpret_cast<void *>(target_oat_va), entrypoint, &m6_slot);
        if (m6_rc != 0 || m6_slot < 0) {
            LOGE("M6b DoHook: shadowhook_m6_install_for_lsplant(.oat=%p, trampoline=%p)"
                 " failed rc=%d slot=%d",
                 (void *)target_oat_va, entrypoint, m6_rc, m6_slot);
            return false;
        }

        /* Step 3: backup entry_point → ART interpreter
         * call_original (cb.backup.invoke) 走 interpreter DEX 路径，不触发 UXN trap。
         * ClassLinker::SetEntryPointsToInterpreter 由 import :class_linker 提供。 */
        if (!ClassLinker::SetEntryPointsToInterpreter(backup)) {
            LOGE("M6b DoHook: SetEntryPointsToInterpreter failed — rolling back PTE install");
            shadowhook_m6_uninstall_for_lsplant(m6_slot);
            return false;
        }

        /* Step 4: 记录 slot + original VA 供 DoUnHook */
        m6_hook_slots_().insert({target, M6HookRecord{m6_slot, target_oat_va}});

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
        int pte_slot = SHADOWHOOK_SLOT_INVALID;
        void *pte_backup = shadowhook_pte_install_for_lsplant_ex(
                              reinterpret_cast<void *>(target_oat_va), entrypoint, &pte_slot);
        if (!pte_backup) {
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
            pte_hook_slots_().insert({target, {pte_slot, target_oat_va}});
        }
#else
        target->SetEntryPoint(entrypoint);   /* M4a 原路径：改 entry_point 到 trampoline */
#endif

        LOGV("Done hook: target(%p:0x%x) -> %p; backup(%p:0x%x) -> %p; hook(%p:0x%x) -> %p", target,
             target->GetAccessFlags(), target->GetEntryPoint(), backup, backup->GetAccessFlags(),
             backup->GetEntryPoint(), hook, hook->GetAccessFlags(), hook->GetEntryPoint());

        return true;
    }
}

bool DoUnHook(ArtMethod *target, ArtMethod *backup) {
#ifndef LSPLANT_M6_BACKEND
    /* Same rationale as DoHook: ScopedSuspendAll requires InitNative, which M6b skips. */
    ScopedGCCriticalSection section(art::Thread::Current(), art::gc::kGcCauseDebugger,
                                    art::gc::kCollectorTypeDebugger);
    ScopedSuspendAll suspend("LSPlant Hook", false);
#endif  /* LSPLANT_M6_BACKEND */
    LOGV("Unhooking: target = %p, backup = %p", target, backup);
#ifdef LSPLANT_M6_BACKEND
    /* M6b DoUnHook: uninstall KPM slot + restore backup entry_point → original OAT VA
     * (so the subsequent CopyFrom propagates the correct VA back to target).
     *
     * Note: target's entry_point was never modified by DoHook (M6b uses PTE.UXN=1
     * instead), so after uninstall the OAT page becomes executable again and the
     * original entry_point in target is still valid — target resumes normal execution
     * after CopyFrom restores the full ArtMethod body. */
    {
        int32_t  m6_slot = -1;
        uint64_t orig_va  = 0;
        m6_hook_slots_().if_contains(target, [&m6_slot, &orig_va](const auto &it) {
            m6_slot = it.second.slot_idx;
            orig_va = it.second.original_oat_va;
        });
        if (m6_slot >= 0) {
            int rc = shadowhook_m6_uninstall_for_lsplant(m6_slot);
            if (rc != 0) {
                LOGE("M6b DoUnHook: shadowhook_m6_uninstall_for_lsplant(slot=%d) failed rc=%d;"
                     " PTE.UXN may still be armed — target will SIGSEGV on OAT fetch.",
                     m6_slot, rc);
                /* Fallthrough: restore backup entry_point and erase slot record anyway.
                 * Leaving the record would block a future re-hook on the same method. */
            }
            /* Restore backup's entry_point to original OAT VA so that the CopyFrom below
             * propagates original_oat_va into target (not the interpreter entry_point that
             * SetEntryPointsToInterpreter wrote during DoHook). */
            backup->SetEntryPoint(reinterpret_cast<void *>(orig_va));
            m6_hook_slots_().erase(target);
        } else {
            LOGE("M6b DoUnHook: no M6 slot record for target — restoring entry_point from target");
            /* backup was set to interpreter by DoHook; target->entry_point was never
             * changed (M6b uses PTE.UXN=1 instead). Propagate target's original OAT VA
             * into backup so CopyFrom(backup) below restores it correctly. */
            backup->SetEntryPoint(target->GetEntryPoint());
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
            /* [M4b-Polish I3 fix, codex round 4+5 P2]: uninstall 失败现实困境的两层处理：
             *
             *   ① PTE 主路径 (slot_for_target >= 0)：调 force_recycle 标记 KPM slot 为 stuck
             *      (PTE 仍 UXN-armed + do_mem_abort handler 仍服务 → target App 不会 SIGSEGV).
             *      LSPlant 视角已"unhooked"但 KPM hook 仍生效；可通过 SH_CMD_PTE_HOOK_STUCK_COUNT
             *      0x7006 查询 stuck 总数, controller 决定是否 kill app + reload KPM.
             *
             *   ② Dobby fallback (slot_for_target == SHADOWHOOK_SLOT_FALLBACK_DOBBY)：rc 来自 DobbyDestroy. 与 PTE telemetry
             *      无关，不走 force_recycle. Dobby far trampoline 可能 leak.
             *
             * 真正的根治需要把 UnHook 上层的 erase 移到 DoUnHook 之后 (lsplant 上游 PR). */
            if (slot_for_target >= 0) {
                /* 真 PTE slot path: mark stuck for telemetry (codex round 2 P1 fix: 不能清 used)
                 * codex round 7 P3 fix: rc 是 long, 用 %ld. */
                LOGE("M4b-PTE shadowhook_pte_uninstall_for_lsplant(slot=%d, .oat=%p) failed rc=%ld; "
                     "marking slot as stuck (telemetry-only: PTE 仍 UXN-armed, do_mem_abort handler 仍服务; "
                     "ghost+slot leak ~16KB+1 entry, query SH_CMD_PTE_HOOK_STUCK_COUNT 决定 reload).",
                     slot_for_target, (void *)original_oat_va, rc);
                /* M4b-Polish I3 (telemetry-only after codex P1): 仅打 stuck 标记, 不释放 slot.
                 * 真正根治 = 移 erase 到 DoUnHook 之后 (上游 PR), 留 follow-up. */
                shadowhook_pte_force_recycle_slot_for_lsplant(slot_for_target);
            } else {
                /* Dobby fallback path: rc 来自 DobbyDestroy. 与 PTE telemetry 无关.
                 * codex round 7 P3 fix: rc 是 long, 用 %ld. */
                LOGE("M4b-Dobby-fallback DobbyDestroy(.oat=%p) failed rc=%ld (slot_for_target=%d sentinel); "
                     "Dobby far trampoline 可能 leak, 但不计入 PTE stuck_count.",
                     (void *)original_oat_va, rc, slot_for_target);
            }
            /* fallthrough: erase 跟踪 + restore entry_point. */
        }
        /* [R2 P1-C 修] 还原 backup.entry_point → original_oat_va：
         * - PTE 路径：pte_backup ghost VA 可能已被 uninstall 释放（成功路径）或仍在（失败路径）
         * - Dobby 路径：origin 指向 Dobby 跳板内 backup 区，DobbyDestroy 拆后跳板可能被释放
         * - 统一改回 original_oat_va 最安全（成功路径下 .oat PTE 已 restore UXN=0，正常可执行；
         *   失败路径下虽然不"最佳"但比悬空指针好）.
         * call_original 之后用 backup 调用：原 .oat 段（成功路径 PTE restore UXN=0）安全可执行. */
        backup->SetEntryPoint(reinterpret_cast<void *>(original_oat_va));
        pte_hook_slots_().erase(target);
    }
#endif
    auto access_flags = target->GetAccessFlags();
    target->CopyFrom(backup);
    target->SetAccessFlags(access_flags);
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
         * M6b skips it so libart .text stays physically unmodified — the
         * entire point of the M6b backend.  ScopedSuspendAll::Init is also
         * part of InitNative; since it is not called, ScopedSuspendAll
         * objects cannot be constructed in DoHook/DoUnHook (gated by
         * #ifndef LSPLANT_M6_BACKEND there). */
        && InitNative(env, info)
#else
        /* M6b: call only the Dobby-free subset needed for DoHook.
         * ArtMethod::Init sets art_method_field + access_flags_offset (no
         * Dobby hooks on API 33).  ClassLinker::InitM6b resolves only the
         * interpreter bridge entry point (no hooks, .as<> lookups only). */
        && InitNativeM6b(env, info)
#endif  /* LSPLANT_M6_BACKEND */
        ;
    return kInit;
}

[[maybe_unused]] jobject Hook(JNIEnv *env, jobject target_method, jobject hooker_object,
                              jobject callback_method) {
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

    if (DoHook(target, hook, backup)) {
        std::apply(
            [backup_method, target_method_id = env->FromReflectedMethod(target_method)](auto... v) {
                ((*v == target_method_id &&
                  (LOGD("Propagate internal used method because of hook"), *v = backup_method)) ||
                 ...);
            },
            kInternalMethods);
        jobject global_backup = JNI_NewGlobalRef(env, reflected_backup);
#ifdef LSPLANT_M6_BACKEND
        /* M6b: Class::Init is not called (avoids Dobby hooks on libart), so
         * GetClassDef_ is unresolved (null).  hooked_classes_ / deoptimized_classes_ /
         * deoptimized_methods_set_ are never consulted in M6b (no SetStatus_ /
         * FixupStaticTrampolines handlers).  Pass nullptr as class_def; hooked_methods_
         * is still populated so UnHook can find and remove the entry. */
        RecordHooked(target, nullptr, global_backup, backup, backup_jmethodid);
#else
        RecordHooked(target, target->GetDeclaringClass()->GetClassDef(), global_backup, backup,
                     backup_jmethodid);
        if (!is_proxy) [[likely]] {
            RecordJitMovement(target, backup);
        } else {
            backuped_proxy_methods_().emplace(backup);
        }
        // Always record backup as deoptimized since we dont want its entrypoint to be updated
        // by FixupStaticTrampolines on hooker class
        // Used hook's declaring class here since backup's is no longer the same with hook's
        RecordDeoptimized(hook->GetDeclaringClass()->GetClassDef(), backup);
#endif  /* LSPLANT_M6_BACKEND */
        return global_backup;
    }

    return nullptr;
}

[[maybe_unused]] bool UnHook(JNIEnv *env, jobject target_method) {
    if (!target_method || !JNI_IsInstanceOf(env, target_method, executable)) {
        LOGE("target method is not an executable");
        return false;
    }
    auto *target = ArtMethod::FromReflectedMethod(env, target_method);
    jobject reflected_backup = nullptr;
    art::ArtMethod *backup = nullptr;
    jmethodID backup_jmethodid = nullptr;
    if (!hooked_methods_().erase_if(
            target, [&reflected_backup, &backup, &backup_jmethodid](const auto &it) {
                std::tie(reflected_backup, backup, backup_jmethodid) = it.second;
                return reflected_backup != nullptr;
            })) {
        LOGE("Unable to unhook a method that is not hooked");
        return false;
    }
    // FIXME: not atomic, but should be fine
    hooked_methods_().erase(backup);
    backuped_proxy_methods_().erase(backup);
#ifndef LSPLANT_M6_BACKEND
    hooked_classes_().erase_if(target->GetDeclaringClass()->GetClassDef(), [&target](auto &it) {
        it.second.erase(target);
        return it.second.empty();
    });
#endif  /* LSPLANT_M6_BACKEND */
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
    env->DeleteGlobalRef(reflected_backup);
    if (DoUnHook(target, backup)) {
        std::apply(
            [backup_method = backup_jmethodid,
             // target_method 是真实的 Java 方法（非 LSPlant 合成品），未被 BackupTo 修改，
             // env->FromReflectedMethod(target_method) 在 opaque-id 模式下安全且返回合法的
             // opaque index，写入 kInternalMethods 后 JNI_Call*Method 可正常使用。
             // （不能用 ArtMethod* 强转——opaque-id 模式下 JNI 不接受指针值作为 jmethodID。）
             target_method_id = env->FromReflectedMethod(target_method)](auto... v) {
                ((*v == backup_method && (LOGD("Propagate internal used method because of unhook"),
                                          *v = target_method_id)) ||
                 ...);
            },
            kInternalMethods);
        return true;
    }
    return false;
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
}
}  // namespace v2

}  // namespace lsplant
