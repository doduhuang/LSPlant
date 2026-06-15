module;

#include <jni.h>
#include <parallel_hashmap/phmap.h>
#include <sys/system_properties.h>

#include <list>
#include <shared_mutex>
#include <string_view>

#include "logging.hpp"

export module lsplant:common;
export import jni_helper;
export import hook_helper;
export import type_traits;

export namespace lsplant {

namespace art {
class ArtMethod;
namespace mirror {
class Class;
}
namespace dex {
class ClassDef {};
}  // namespace dex

}  // namespace art

template <class K, class V, class Hash = phmap::priv::hash_default_hash<K>,
          class Eq = phmap::priv::hash_default_eq<K>,
          class Alloc = phmap::priv::Allocator<phmap::priv::Pair<const K, V>>, size_t N = 4>
using SharedHashMap = phmap::parallel_flat_hash_map<K, V, Hash, Eq, Alloc, N, std::shared_mutex>;

template <class T, class Hash = phmap::priv::hash_default_hash<T>,
          class Eq = phmap::priv::hash_default_eq<T>, class Alloc = phmap::priv::Allocator<T>,
          size_t N = 4>
using SharedHashSet = phmap::parallel_flat_hash_set<T, Hash, Eq, Alloc, N, std::shared_mutex>;

template <typename T>
constexpr inline auto RoundUpTo(T v, size_t size) {
    return v + size - 1 - ((v + size - 1) & (size - 1));
}

[[gnu::const]] inline auto GetAndroidApiLevel() {
    static auto kApiLevel = [] {
        std::array<char, PROP_VALUE_MAX> prop_value;
        __system_property_get("ro.build.version.sdk", prop_value.data());
        return atoi(prop_value.data());
    }();
    [[assume(kApiLevel >= __ANDROID_API__)]];
    return kApiLevel;
}

inline auto IsJavaDebuggable(JNIEnv * env) {
    static auto kDebuggable = [&env]() {
        auto sdk_int = GetAndroidApiLevel();
        if (sdk_int < __ANDROID_API_P__) {
            return false;
        }
        auto runtime_class = JNI_FindClass(env, "dalvik/system/VMRuntime");
        if (!runtime_class) {
            LOGE("Failed to find VMRuntime");
            return false;
        }
        auto get_runtime_method = JNI_GetStaticMethodID(env, runtime_class, "getRuntime",
                                                        "()Ldalvik/system/VMRuntime;");
        if (!get_runtime_method) {
            LOGE("Failed to find VMRuntime.getRuntime()");
            return false;
        }
        auto is_debuggable_method =
            JNI_GetMethodID(env, runtime_class, "isJavaDebuggable", "()Z");
        if (!is_debuggable_method) {
            LOGE("Failed to find VMRuntime.isJavaDebuggable()");
            return false;
        }
        auto runtime = JNI_CallStaticObjectMethod(env, runtime_class, get_runtime_method);
        if (!runtime) {
            LOGE("Failed to get VMRuntime");
            return false;
        }
        bool is_debuggable = JNI_CallBooleanMethod(env, runtime, is_debuggable_method);
        LOGD("java runtime debuggable %s", is_debuggable ? "true" : "false");
        return is_debuggable;
    }();
    return kDebuggable;
}

constexpr auto kPointerSize = sizeof(void *);

// shadowhook: 值从 pair<jobject, ArtMethod*> 扩展为 tuple<jobject, ArtMethod*, jmethodID>，
// 其中第三个元素是在 Hook 时（DoHook 之前，backup 未被 BackupTo 污染时）取到的 backup
// 的 jmethodID（opaque 模式下是 opaque index，pointer 模式下是 ArtMethod* 强转）。
// 存入这个值是为了让 UnHook 时的 kInternalMethods 传播在 opaque jni ids 模式下也能正确
// 比较，而不必在 UnHook 时重新调用 env->FromReflectedMethod（那时 backup 已被 BackupTo
// 覆写，DexMethodIndex 变成 target 的，ART EncodeGenericId 会越界崩溃）。
// 对 backup 的辅助条目（nullptr, target, 0）第三字段不使用，置 0。
//
// shadowhook M5.2g.3.1 root cause fix: 这些全局 SharedHashMap/Set/list 默认构造的
// init_array 顺序与 jni_bridge.cpp 的 __attribute__((constructor)) 顺序不可控.
// 当 dlopen-loaded ctor 比 lsplant.cc 的静态全局更早 init 时, lsplant::Init 在 ctor 里被调用
// → InitNative 安装 Class::SetStatus hook → 任何 class init (verifyClass) 调 SetStatus
// → hook callback 调 BackupClassMethods → hooked_classes_().if_contains() → phmap ctrl_=0
// (bss zero-init, 未构造) → SIGSEGV at 0x0 inside VerifyClass+216.
// 修复: 用 Meyer's singleton (函数内 static, 首次访问惰性构造, thread-safe) 绕开 init_array 顺序.

inline auto& hooked_methods_() {
    static SharedHashMap<art::ArtMethod *, std::tuple<jobject, art::ArtMethod *, jmethodID>>
        instance;
    return instance;
}

/* M4b.3 PTE/UXN 路径：DoHook 装 KPM slot 后存 (target → record)，DoUnHook 拆 KPM slot 时用
 *   - slot_idx >= 0：PTE 主路径，原始 .oat VA 在 original_oat_va，调
 *                    shadowhook_pte_uninstall_for_lsplant(slot) + 把 target 的
 *                    entry_point 还原到 original_oat_va（防 CopyFrom 把
 *                    pte_backup ghost VA 灌回 target 后该页已 free → 悬空）
 *   - slot_idx == -2：PTE 失败走了 Dobby fallback，记 original_oat_va 让
 *                     DoUnHook 调 DobbyDestroy(original_oat_va) 拆 Dobby inline.
 * 复用 Meyer's singleton 模式与同文件其它全局一致 [M4b.3 R1+R2 P1 修：完整 unhook 语义]. */
struct PteHookRecord {
    int32_t  slot_idx;          /* >=0 PTE slot；-2 Dobby fallback；其它无效不应入表 */
    uint64_t original_oat_va;   /* DoHook 时拷的 target->GetEntryPoint() — DoUnHook 还原用 */
};
inline auto& pte_hook_slots_() {
    static SharedHashMap<art::ArtMethod *, PteHookRecord> instance;
    return instance;
}

#ifdef LSPLANT_M6_BACKEND
/* Per-ArtMethod record of the M6 PTE/UXN slot and the original OAT entry VA.
 * Used by DoUnHook to call shadowhook_m6_uninstall_for_lsplant + restore entry.
 *
 * slot_idx: KPM slot returned by SH_CMD_M6_SIMPLE_HOOK (≥0 valid)
 * original_oat_va: ArtMethod entry_point BEFORE hook install, restored on unhook.
 *
 * Meyer's singleton pattern: same rationale as pte_hook_slots_() above — avoids
 * init_array order fiasco when lsplant is dlopen-loaded from a ctor context. */
struct M6HookRecord {
    int32_t  slot_idx;        /* bridge slot idx returned by shadowhook_m6_install_for_lsplant */
    uint64_t original_oat_va; /* ArtMethod entry_point BEFORE hook install */
};

inline auto& m6_hook_slots_() {
    static SharedHashMap<art::ArtMethod *, M6HookRecord> instance;
    return instance;
}
#endif  /* LSPLANT_M6_BACKEND */

inline auto& hooked_classes_() {
    static SharedHashMap<const art::dex::ClassDef *, phmap::flat_hash_set<art::ArtMethod *>>
        instance;
    return instance;
}

inline auto& deoptimized_methods_set_() {
    static SharedHashSet<art::ArtMethod *> instance;
    return instance;
}

inline auto& deoptimized_classes_() {
    static SharedHashMap<const art::dex::ClassDef *, phmap::flat_hash_set<art::ArtMethod *>>
        instance;
    return instance;
}

inline auto& backuped_proxy_methods_() {
    static SharedHashSet<art::ArtMethod *> instance;
    return instance;
}

inline auto& jit_movements_() {
    static std::list<std::pair<art::ArtMethod *, art::ArtMethod *>> instance;
    return instance;
}

inline auto& jit_movements_lock_() {
    static std::shared_mutex instance;
    return instance;
}

inline art::ArtMethod *IsHooked(art::ArtMethod * art_method, bool including_backup = false) {
    art::ArtMethod *backup = nullptr;
    hooked_methods_().if_contains(art_method, [&backup, &including_backup](const auto &it) {
        // tuple: (reflected_backup jobject, backup ArtMethod*, backup jmethodID)
        // target 条目：reflected_backup 非 null；backup 条目：reflected_backup = null
        if (including_backup || std::get<0>(it.second)) backup = std::get<1>(it.second);
    });
    return backup;
}

inline art::ArtMethod *IsBackup(art::ArtMethod * art_method) {
    art::ArtMethod *backup = nullptr;
    hooked_methods_().if_contains(art_method, [&backup](const auto &it) {
        if (!std::get<0>(it.second)) backup = std::get<1>(it.second);
    });
    return backup;
}

inline bool IsDeoptimized(art::ArtMethod * art_method) {
    return deoptimized_methods_set_().contains(art_method);
}

inline std::list<std::pair<art::ArtMethod *, art::ArtMethod *>> GetJitMovements() {
    std::unique_lock lk(jit_movements_lock_());
    return std::move(jit_movements_());
}

// shadowhook: 增加 backup_jmethodid 参数——Hook 时在 DoHook 之前（backup 未被 BackupTo
// 污染时）取到的 opaque jmethodID，存入 tuple 第三字段，供 UnHook kInternalMethods 传播用。
inline void RecordHooked(art::ArtMethod * target, const art::dex::ClassDef *class_def,
                         jobject reflected_backup, art::ArtMethod *backup,
                         jmethodID backup_jmethodid) {
    hooked_classes_().lazy_emplace_l(
        class_def, [&target](auto &it) { it.second.emplace(target); },
        [&class_def, &target](const auto &ctor) {
            ctor(class_def, phmap::flat_hash_set<art::ArtMethod *>{target});
        });
    hooked_methods_().insert(
        {std::make_pair(target,
                        std::make_tuple(reflected_backup, backup, backup_jmethodid)),
         // backup 的辅助条目：reflected_backup=null 区分身份，jmethodid 置 nullptr（不使用）
         std::make_pair(backup, std::make_tuple(nullptr, target, static_cast<jmethodID>(nullptr)))});
}

inline void RecordDeoptimized(const art::dex::ClassDef *class_def, art::ArtMethod *art_method) {
    { deoptimized_classes_()[class_def].emplace(art_method); }
    deoptimized_methods_set_().insert(art_method);
}

inline void RecordJitMovement(art::ArtMethod * target, art::ArtMethod * backup) {
    std::unique_lock lk(jit_movements_lock_());
    jit_movements_().emplace_back(target, backup);
}
}  // namespace lsplant
