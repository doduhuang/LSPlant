module;

#include "lsplant.hpp"

export module lsplant;

export namespace lsplant::inline v2{
    using lsplant::v2::InitInfo;
    using lsplant::v2::Init;
    using lsplant::v2::M6TransactionHealthy;
    using lsplant::v2::M6CommitWithSuspendedThreads;
    using lsplant::v2::Hook;
    using lsplant::v2::HookWithBackupPublisher;
    using lsplant::v2::UnHook;
    using lsplant::v2::UnHookAll;
    using lsplant::v2::IsHooked;
    using lsplant::v2::Deoptimize;
    using lsplant::v2::GetNativeFunction;
    using lsplant::v2::MakeClassInheritable;
    using lsplant::v2::MakeDexFileTrusted;
}
