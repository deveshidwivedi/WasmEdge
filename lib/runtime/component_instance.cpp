#include "runtime/instance/component.h"

namespace WasmEdge {
namespace Runtime {
namespace Instance {

using namespace AST::Component;

namespace {
void typeConvert(ValueType &VT, const ValType &Ty) noexcept {
  switch (Ty.getCode()) {
  case TypeCode::I8:
    VT.emplace<PrimValType>(PrimValType::S8);
    break;
  case TypeCode::I16:
    VT.emplace<PrimValType>(PrimValType::S16);
    break;
  case TypeCode::I32:
    VT.emplace<PrimValType>(PrimValType::S32);
    break;
  case TypeCode::I64:
    VT.emplace<PrimValType>(PrimValType::S64);
    break;
  case TypeCode::F32:
    VT.emplace<PrimValType>(PrimValType::Float32);
    break;
  case TypeCode::F64:
    VT.emplace<PrimValType>(PrimValType::Float64);
    break;

  default:
    break;
  }
}

void typeConvert(FuncType &FT, const AST::FunctionType &Ty) noexcept {
  auto &PL = FT.getParamList();
  for (auto const &PT : Ty.getParamTypes()) {
    LabelValType L{};
    typeConvert(L.getValType(), PT);
    PL.emplace_back(L);
  }
  auto &RL = FT.getResultList();
  if (Ty.getReturnTypes().size() == 1) {
    typeConvert(RL.emplace<ValueType>(), Ty.getReturnTypes()[0]);
  } else {
    auto &LL = RL.emplace<std::vector<LabelValType>>();
    for (auto const &RT : Ty.getReturnTypes()) {
      LabelValType L{};
      typeConvert(L.getValType(), RT);
      LL.emplace_back(L);
    }
  }
}
} // namespace

std::string_view ComponentInstance::getComponentName() const noexcept {
  return CompName;
}

void ComponentInstance::addModule(const AST::Module &M) noexcept {
  ModList.emplace_back(M);
}
const AST::Module &ComponentInstance::getModule(uint32_t Index) const noexcept {
  return ModList[Index];
}

void ComponentInstance::addComponent(
    const AST::Component::Component &C) noexcept {
  CompList.emplace_back(C);
}
const AST::Component::Component &
ComponentInstance::getComponent(uint32_t Index) const noexcept {
  return CompList[Index];
}

void ComponentInstance::addModuleInstance(ModuleInstance *Inst) noexcept {
  ModInstList.push_back(std::move(Inst));
}
void ComponentInstance::addModuleInstance(
    std::unique_ptr<ModuleInstance> Inst) noexcept {
  ModInstList.push_back(Inst.get());
  OwnedModInstList.push_back(std::move(Inst));
}
const ModuleInstance *
ComponentInstance::getModuleInstance(uint32_t Index) const noexcept {
  return ModInstList[Index];
}

void ComponentInstance::addComponentInstance(
    const ComponentInstance *Inst) noexcept {
  CompInstList.push_back(Inst);
}
void ComponentInstance::addComponentInstance(
    std::unique_ptr<ComponentInstance> Inst) noexcept {
  CompInstList.push_back(Inst.get());
  OwnedCompInstList.push_back(std::move(Inst));
}
const ComponentInstance *
ComponentInstance::getComponentInstance(uint32_t Index) const noexcept {
  return CompInstList[Index];
}

void ComponentInstance::addHostFunc(
    std::string_view Name,
    std::unique_ptr<WasmEdge::Runtime::Component::HostFunctionBase> &&Func) {
  addCoreFuncType(Func->getFuncType());
  auto FuncInst =
      std::make_unique<Instance::Component::FunctionInstance>(std::move(Func));
  unsafeAddHostFunc(Name, std::move(FuncInst));
}
void ComponentInstance::addHostFunc(
    std::string_view Name,
    std::unique_ptr<Component::FunctionInstance> &&Func) {
  addCoreFuncType(Func->getFuncType());
  unsafeAddHostFunc(Name, std::move(Func));
}

void ComponentInstance::addCoreFunctionInstance(
    std::unique_ptr<FunctionInstance> &&Inst) noexcept {
  addCoreFunctionInstance(Inst.get());
  OwnedCoreFuncInstList.emplace_back(std::move(Inst));
}
void ComponentInstance::addCoreFunctionInstance(
    FunctionInstance *Inst) noexcept {
  CoreFuncInstList.push_back(Inst);
}
FunctionInstance *
ComponentInstance::getCoreFunctionInstance(uint32_t Index) const noexcept {
  return CoreFuncInstList[Index];
}

void ComponentInstance::addFunctionInstance(
    std::unique_ptr<Component::FunctionInstance> Inst) noexcept {
  addFunctionInstance(Inst.get());
  OwnedFuncInstList.emplace_back(std::move(Inst));
}
void ComponentInstance::addFunctionInstance(
    Component::FunctionInstance *Inst) noexcept {
  FuncInstList.push_back(Inst);
}
Component::FunctionInstance *
ComponentInstance::getFunctionInstance(uint32_t Index) const noexcept {
  return FuncInstList[Index];
}

ValInterface ComponentInstance::getValue(uint32_t Index) const noexcept {
  return ValueList[Index];
}
void ComponentInstance::setValue(uint32_t Index, ValInterface V) noexcept {
  ValueList[Index] = V;
}

void ComponentInstance::addExport(std::string_view Name,
                                  const ModuleInstance *Inst) noexcept {
  ExportModuleMap.emplace(Name, Inst);
}
const ModuleInstance *
ComponentInstance::findModuleExports(std::string_view Name) const noexcept {
  return ExportModuleMap.at(std::string(Name));
}
void ComponentInstance::addExport(std::string_view Name,
                                  Component::FunctionInstance *Inst) noexcept {
  ExportFuncMap.insert_or_assign(std::string(Name), Inst);
}
Component::FunctionInstance *
ComponentInstance::findFuncExports(std::string_view Name) const noexcept {
  return ExportFuncMap.at(std::string(Name));
}
std::vector<std::pair<std::string, const AST::FunctionType &>>
ComponentInstance::getFuncExports() const noexcept {
  std::vector<std::pair<std::string, const AST::FunctionType &>> R;
  R.reserve(ExportFuncMap.size());
  for (auto &&[Name, Func] : ExportFuncMap) {
    const auto &FuncType = Func->getFuncType();
    R.emplace_back(Name, FuncType);
  }
  return R;
}

void ComponentInstance::addCoreTableInstance(TableInstance *Inst) noexcept {
  CoreTabInstList.push_back(Inst);
}
TableInstance *
ComponentInstance::getCoreTableInstance(uint32_t Index) const noexcept {
  return CoreTabInstList[Index];
}

void ComponentInstance::addCoreMemoryInstance(MemoryInstance *Inst) noexcept {
  CoreMemInstList.push_back(Inst);
}
MemoryInstance *
ComponentInstance::getCoreMemoryInstance(uint32_t Index) const noexcept {
  return CoreMemInstList[Index];
}

void ComponentInstance::addCoreGlobalInstance(GlobalInstance *Inst) noexcept {
  CoreGlobInstList.push_back(Inst);
}
GlobalInstance *
ComponentInstance::getCoreGlobalInstance(uint32_t Index) const noexcept {
  return CoreGlobInstList[Index];
}

void ComponentInstance::addCoreType(const CoreDefType &Ty) noexcept {
  CoreTypes.emplace_back(Ty);
}
const CoreDefType ComponentInstance::getCoreType(uint32_t Idx) const noexcept {
  return CoreTypes[Idx];
}

void ComponentInstance::addHostType(std::string_view Name,
                                    PrimValType &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    RecordTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    VariantTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    ListTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    TupleTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    Flags &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    EnumTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    OptionTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    ResultTy &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    Own &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    Borrow &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    FuncType &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    ResourceType &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    ComponentType &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}
void ComponentInstance::addHostType(std::string_view Name,
                                    InstanceType &&Type) noexcept {
  addType(Type);
  ExportTypesMap.emplace(std::string(Name), std::move(Type));
}

const AST::Component::DefType
ComponentInstance::getType(std::string_view Name) const noexcept {
  return ExportTypesMap.at(std::string(Name));
}
void ComponentInstance::addCoreFuncType(const AST::FunctionType &Ty) noexcept {
  FuncType FT{};
  typeConvert(FT, Ty);
  addType(FT);
}
void ComponentInstance::addType(DefType Ty) noexcept { Types.emplace_back(Ty); }
const DefType ComponentInstance::getType(uint32_t Idx) const noexcept {
  // spdlog::info("get type from component at index {}", Idx);
  // spdlog::info("component `{}` has {} types", CompName, Types.size());
  return Types[Idx];
}
TypeIndex ComponentInstance::getLastTypeIndex() noexcept {
  return static_cast<TypeIndex>(Types.size() - 1);
}
TypeIndex ComponentInstance::typeToIndex(DefType Ty) noexcept {
  addType(Ty);
  return getLastTypeIndex();
}

std::shared_ptr<ResourceHandle>
ComponentInstance::removeResource(uint32_t ResourceTypeIndex,
                                  uint32_t HandleIndex) noexcept {
  auto ResourceMap = Resources[ResourceTypeIndex];
  auto Handle = std::move(ResourceMap[HandleIndex]);
  ResourceMap.erase(HandleIndex);
  return Handle;
}

} // namespace Instance
} // namespace Runtime
} // namespace WasmEdge
