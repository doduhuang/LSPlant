/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * shadowhook_lsplant_abi.h —— shadowhook ↔ lsplant fork 共享 ABI 常量
 *
 * 【这个文件是什么】
 *   lsplant fork (third_party/lsplant) 和 shadowhook bridge (lsplant_glue.cpp) 都
 *   要识别 sh_pte_hook_install_for_lsplant_ex 返回的 slot_idx 特殊值（-1=invalid /
 *   -2=Dobby fallback）。两边以前各自硬编码 magic '-1'/'-2'，rebase fork 时极易
 *   两边漂移。本文件单一真源.
 *
 * 【canonical 路径 vs vendored 副本】
 *   - canonical: <SH_ROOT>/include/shadowhook_lsplant_abi.h（本文件）
 *   - vendored: third_party/lsplant/lsplant/src/main/jni/shadowhook_lsplant_abi.h
 *     让 lsplant fork standalone build (无 SH_ROOT include path) 也能工作。
 *
 *   ⚠ 改 ABI 值/添加 sentinel 时必须同步更新两份。两份均为 2 个 constexpr int32_t，
 *     预期长期不变。bridge/CMakeLists.txt 对 lsplant_static 暴露 SH_ROOT/include —
 *     quoted include 编译器先搜源文件目录 (jni/) 故 standalone 用 vendored 副本，
 *     shadowhook build 因 quoted-include 也优先 jni/ 副本（与 canonical 等价）。
 *
 * 【M4b-Polish T3 I2 fix (M4b.3-T1 reviewer Important-2)】
 *   把 'magic number cross-module' anti-pattern 抽成共享 header.
 */
#ifndef SHADOWHOOK_LSPLANT_ABI_H
#define SHADOWHOOK_LSPLANT_ABI_H

/* slot_idx 特殊值（int32_t 出参）：
 *   -1 = 安装失败（hooker = nullptr）/ 既有 slot 未占用
 *   -2 = PTE 路径失败但 Dobby fallback 装好（slot 在 KPM 端无对应 entry，
 *        backup 是 Dobby origin；DoUnHook 路径不调 sh_pte_hook_uninstall） */
#define SHADOWHOOK_SLOT_INVALID         (-1)
#define SHADOWHOOK_SLOT_FALLBACK_DOBBY  (-2)

/* R2-CM-04: 与 <SH_ROOT>/include/shadowhook_lsplant_abi.h 保持同步. */
#define SH_M6_OK                (0)
#define SH_M6_E_INVAL           (-22)
#define SH_M6_E_NOSPC           (-28)
#define SH_M6_E_FAULT           (-14)
#define SH_M6_E_NOENT           (-2)
#define SH_M6_E_PMD             (-34)
#define SH_M6_E_GENERIC         (-1)

#endif /* SHADOWHOOK_LSPLANT_ABI_H */
