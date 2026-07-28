module;

#include <jni.h>
#include <parallel_hashmap/phmap.h>
#include <sys/system_properties.h>

#include <list>
#include <new>
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

// shadowhook: value tuple stores reflected backup, backup ArtMethod, and the
// pre-DoHook jmethodIDs for both backup and target.  Persisting both IDs lets
// UnHookAll restore kInternalMethods without reflecting a BackupTo-mutated
// method (unsafe with opaque JNI IDs) and without needing a target jobject.
//
// shadowhook M5.2g.3.1 root cause fix: 这些全局 SharedHashMap/Set/list 默认构造的
// init_array 顺序与 jni_bridge.cpp 的 __attribute__((constructor)) 顺序不可控.
// 当 dlopen-loaded ctor 比 lsplant.cc 的静态全局更早 init 时, lsplant::Init 在 ctor 里被调用
// → InitNative 安装 Class::SetStatus hook → 任何 class init (verifyClass) 调 SetStatus
// → hook callback 调 BackupClassMethods → hooked_classes_().if_contains() → phmap ctrl_=0
// (bss zero-init, 未构造) → SIGSEGV at 0x0 inside VerifyClass+216.
// 修复: 用 Meyer's singleton (函数内 static, 首次访问惰性构造, thread-safe) 绕开 init_array 顺序.

inline auto& hooked_methods_() {
    static SharedHashMap<
        art::ArtMethod *,
        std::tuple<jobject, art::ArtMethod *, jmethodID, jmethodID>>
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
    int32_t  slot_idx;                /* PTE/UXN: bridge slot idx (≥0); entry_point fallback: -1 */
    uint64_t original_oat_va;         /* ArtMethod entry_point BEFORE hook install，unhook 时还原 */
    bool     is_entry_point_fallback; /* true = /apex/ 系统类走 SetEntryPoint+shim; false = PTE/UXN */
    uint64_t shim_va;                 /* fallback 专用：命名 shim 页 VA（PTE/UXN 时 0），unhook 时 munmap */
    /*
     * REGISTERING 在 KPM syscall 前预占 map 节点，保证 syscall 成功后只做不分配内存的
     * modify_if；STAGED 等待 ARM_PAGES；PASS_THROUGH 是 smart_uninstall rc=1 后可 rehook
     * 的常驻 slot；POISONED 表示 backend rollback 结果未知，进程必须停止后续 commit。
     */
    enum class State {
        kRegistering,
        kStaged,
        kPassThrough,
        kPoisoned,
    } state;
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
        // tuple: (reflected_backup, backup ArtMethod*, backup ID, target ID)
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

inline bool RecordHooked(art::ArtMethod * target, const art::dex::ClassDef *class_def,
                         jobject reflected_backup, art::ArtMethod *backup,
                         jmethodID backup_jmethodid, jmethodID target_jmethodid) {
    bool primary_inserted = false;
    bool backup_inserted = false;
    try {
        primary_inserted = hooked_methods_()
            .insert(std::make_pair(
                target, std::make_tuple(reflected_backup, backup,
                                        backup_jmethodid, target_jmethodid)))
            .second;
        if (!primary_inserted) return false;

        backup_inserted = hooked_methods_()
            .insert(std::make_pair(
                backup,
                std::make_tuple(nullptr, target,
                                static_cast<jmethodID>(nullptr),
                                static_cast<jmethodID>(nullptr))))
            .second;
        if (!backup_inserted) {
            hooked_methods_().erase(target);
            return false;
        }

        if (class_def) {
            hooked_classes_().lazy_emplace_l(
                class_def, [&target](auto &it) { it.second.emplace(target); },
                [&class_def, &target](const auto &ctor) {
                    ctor(class_def, phmap::flat_hash_set<art::ArtMethod *>{target});
                });
        }
        return true;
    } catch (const std::bad_alloc &) {
        if (backup_inserted) hooked_methods_().erase(backup);
        if (primary_inserted) hooked_methods_().erase(target);
        if (class_def) {
            hooked_classes_().erase_if(class_def, [&target](auto &it) {
                it.second.erase(target);
                return it.second.empty();
            });
        }
        return false;
    }
}

inline void ForgetHookedRecord(art::ArtMethod *target,
                               const art::dex::ClassDef *class_def,
                               art::ArtMethod *backup) {
    hooked_methods_().erase(backup);
    hooked_methods_().erase(target);
    if (class_def) {
        hooked_classes_().erase_if(class_def, [&target](auto &it) {
            it.second.erase(target);
            return it.second.empty();
        });
    }
}

/*
 * All auxiliary records required by a live hook must be allocated before
 * ArtMethod/entry-point mutation.  Returning from DoHook with a live target
 * and then growing one of these containers leaves no safe failure rollback.
 */
struct HookAuxRecords {
    bool jit_movement = false;
    bool proxy_backup = false;
    bool deoptimized_class = false;
    bool deoptimized_method = false;
};

inline void ForgetHookAuxRecords(
        art::ArtMethod *target, art::ArtMethod *backup,
        const art::dex::ClassDef *deoptimized_class_def,
        HookAuxRecords *state) noexcept {
    if (!state) return;
    try {
        if (state->deoptimized_method) {
            deoptimized_methods_set_().erase(backup);
            state->deoptimized_method = false;
        }
        if (state->deoptimized_class && deoptimized_class_def) {
            deoptimized_classes_().erase_if(
                deoptimized_class_def, [&backup](auto &it) {
                    it.second.erase(backup);
                    return it.second.empty();
                });
            state->deoptimized_class = false;
        }
        if (state->proxy_backup) {
            backuped_proxy_methods_().erase(backup);
            state->proxy_backup = false;
        }
        if (state->jit_movement) {
            std::unique_lock lk(jit_movements_lock_());
            for (auto it = jit_movements_().begin();
                 it != jit_movements_().end(); ++it) {
                if (it->first == target && it->second == backup) {
                    jit_movements_().erase(it);
                    break;
                }
            }
            state->jit_movement = false;
        }
    } catch (...) {
        /* Rollback is best effort only for an impossible mutex/container
         * exception. DoHook still refuses to activate the target. */
    }
}

inline bool RecordHookAuxRecords(
        art::ArtMethod *target, art::ArtMethod *backup, bool is_proxy,
        const art::dex::ClassDef *deoptimized_class_def,
        HookAuxRecords *state) noexcept {
    if (!target || !backup || !deoptimized_class_def || !state) return false;
    *state = {};
    try {
        if (is_proxy) {
            state->proxy_backup =
                backuped_proxy_methods_().insert(backup).second;
            if (!state->proxy_backup) return false;
        } else {
            std::unique_lock lk(jit_movements_lock_());
            jit_movements_().emplace_back(target, backup);
            state->jit_movement = true;
        }

        deoptimized_classes_().lazy_emplace_l(
            deoptimized_class_def,
            [state, backup](auto &it) {
                state->deoptimized_class =
                    it.second.emplace(backup).second;
            },
            [state, deoptimized_class_def, backup](const auto &ctor) {
                phmap::flat_hash_set<art::ArtMethod *> methods;
                state->deoptimized_class = methods.emplace(backup).second;
                ctor(deoptimized_class_def, std::move(methods));
            });
        if (!state->deoptimized_class) {
            ForgetHookAuxRecords(
                target, backup, deoptimized_class_def, state);
            return false;
        }

        state->deoptimized_method =
            deoptimized_methods_set_().insert(backup).second;
        if (!state->deoptimized_method) {
            ForgetHookAuxRecords(
                target, backup, deoptimized_class_def, state);
            return false;
        }
        return true;
    } catch (...) {
        ForgetHookAuxRecords(target, backup, deoptimized_class_def, state);
        return false;
    }
}

inline void RecordDeoptimized(const art::dex::ClassDef *class_def,
                              art::ArtMethod *art_method) {
    /* Deoptimize() is a legacy public API without a rollback return channel.
     * Hook installation does not use this helper; it uses the transactional
     * RecordHookAuxRecords() path above. */
    { deoptimized_classes_()[class_def].emplace(art_method); }
    deoptimized_methods_set_().insert(art_method);
}
}  // namespace lsplant
