// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2019-2024 Second State INC

#include "system/stacktrace.h"
#include "common/spdlog.h"
#include <fmt/ranges.h>

#if WASMEDGE_OS_WINDOWS
#include "system/winapi.h"
#else
#include <execinfo.h>
#endif

namespace WasmEdge {

Span<void *const> stackTrace(Span<void *> Buffer) noexcept {
#if WASMEDGE_OS_WINDOWS
  winapi::STACKFRAME64_ StackFrame;
  winapi::CONTEXT_ C;
  winapi::RtlCaptureContext(&C);
  C.ContextFlags = winapi::CONTEXT_CONTROL_ | winapi::CONTEXT_INTEGER_;
  winapi::DWORD_ MachineType = winapi::IMAGE_FILE_MACHINE_UNKNOWN_;
#if defined(_M_X64)
  StackFrame.AddrPC.Offset = C.Rip;
  StackFrame.AddrStack.Offset = C.Rsp;
  StackFrame.AddrFrame.Offset = C.Rbp;
  MachineType = winapi::IMAGE_FILE_MACHINE_AMD64_;
#elif defined(_M_IX86)
  StackFrame.AddrPC.Offset = C.Eip;
  StackFrame.AddrStack.Offset = C.Esp;
  StackFrame.AddrFrame.Offset = C.Ebp;
  MachineType = winapi::IMAGE_FILE_MACHINE_I386_;
#elif defined(_M_ARM64)
  StackFrame.AddrPC.Offset = C.Pc;
  StackFrame.AddrStack.Offset = C.Sp;
  StackFrame.AddrFrame.Offset = C.Fp;
  MachineType = winapi::IMAGE_FILE_MACHINE_ARM64_;
#elif defined(_M_ARM)
  StackFrame.AddrPC.Offset = C.Pc;
  StackFrame.AddrStack.Offset = C.Sp;
  StackFrame.AddrFrame.Offset = C.R11;
  MachineType = winapi::IMAGE_FILE_MACHINE_ARMNT_;
#endif
  StackFrame.AddrPC.Mode = winapi::AddrModeFlat;
  StackFrame.AddrStack.Mode = winapi::AddrModeFlat;
  StackFrame.AddrFrame.Mode = winapi::AddrModeFlat;
  size_t Depth = 0;
  while (winapi::StackWalk64(MachineType, winapi::GetCurrentProcess(),
                             winapi::GetCurrentThread(), &StackFrame, &C,
                             nullptr, &SymFunctionTableAccess64,
                             &SymGetModuleBase64, nullptr)) {
    if (StackFrame.AddrFrame.Offset == 0) {
      break;
    }
    Buffer[Depth++] = reinterpret_cast<void *>(StackFrame.AddrPC.Offset);
    if (Depth >= Buffer.size()) {
      break;
    }
  }
  return Buffer.first(Depth);
#else
  auto Size = backtrace(Buffer.data(), Buffer.size());
  return Buffer.first(Size);
#endif
}

Span<const uint32_t>
interpreterStackTrace(const Runtime::StackManager &StackMgr,
                      Span<uint32_t> Buffer) noexcept {
  size_t Index = 0;
  if (auto Module = StackMgr.getModule()) {
    const auto FuncInsts = Module->getFunctionInstances();
    std::map<AST::InstrView::iterator, int64_t> Funcs;
    for (size_t I = 0; I < FuncInsts.size(); ++I) {
      const auto &Func = FuncInsts[I];
      if (Func && Func->isWasmFunction()) {
        const auto &Instrs = Func->getInstrs();
        Funcs.emplace(Instrs.end(), INT64_C(-1));
        Funcs.emplace(Instrs.begin(), I);
      }
    }
    for (const auto &Frame : StackMgr.getFramesSpan()) {
      auto Entry = Frame.From;
      auto Iter = Funcs.lower_bound(Entry);
      if ((Iter == Funcs.end() || Iter->first > Entry) &&
          Iter != Funcs.begin()) {
        --Iter;
      }
      if (Iter != Funcs.end() && Iter->first < Entry &&
          Iter->second >= INT64_C(0) && Index < Buffer.size()) {
        Buffer[Index++] = static_cast<uint32_t>(Iter->second);
      }
    }
  }
  return Buffer.first(Index);
}

Span<const uint32_t> compiledStackTrace(const Runtime::StackManager &StackMgr,
                                        Span<uint32_t> Buffer) noexcept {
  std::array<void *, 256> StackTraceBuffer;
  return compiledStackTrace(StackMgr, stackTrace(StackTraceBuffer), Buffer);
}

Span<const uint32_t> compiledStackTrace(const Runtime::StackManager &StackMgr,
                                        Span<void *const> Stack,
                                        Span<uint32_t> Buffer) noexcept {
  std::map<void *, int64_t> Funcs;
  size_t Index = 0;
  if (auto Module = StackMgr.getModule()) {
    const auto FuncInsts = Module->getFunctionInstances();
    for (size_t I = 0; I < FuncInsts.size(); ++I) {
      const auto &Func = FuncInsts[I];
      if (Func && Func->isCompiledFunction()) {
        Funcs.emplace(
            reinterpret_cast<void *>(Func->getFuncType().getSymbol().get()),
            INT64_C(-1));
        Funcs.emplace(Func->getSymbol().get(), I);
      }
    }
    for (auto Entry : Stack) {
      auto Iter = Funcs.lower_bound(Entry);
      if ((Iter == Funcs.end() || Iter->first > Entry) &&
          Iter != Funcs.begin()) {
        --Iter;
      }
      if (Iter != Funcs.end() && Iter->first < Entry &&
          Iter->second >= INT64_C(0) && Index < Buffer.size()) {
        Buffer[Index++] = static_cast<uint32_t>(Iter->second);
      }
    }
  }
  return Buffer.first(Index);
}

void dumpStackTrace(Span<const uint32_t> Stack) noexcept {
  using namespace std::literals;
  spdlog::error("calling stack:{}"sv, fmt::join(Stack, ", "sv));
}

} // namespace WasmEdge
