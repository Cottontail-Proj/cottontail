// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include "Pass.h"

#include <llvm/ADT/SmallVector.h>
#include <llvm/CodeGen/IntrinsicLowering.h>
#include <llvm/CodeGen/TargetLowering.h>
#include <llvm/CodeGen/TargetSubtargetInfo.h>
#include <llvm/IR/InstIterator.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Target/TargetOptions.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#if LLVM_VERSION_MAJOR < 14
#include <llvm/Support/TargetRegistry.h>
#else
#include <llvm/MC/TargetRegistry.h>
#endif

#include "Runtime.h"
#include "Symbolizer.h"

extern std::map<std::string, std::map<int32_t, std::string>> switch_case_map;
//std::map<std::string, std::vector<int32_t>> switch_case_map_all;
//extern std::string global_str;

#include <iostream>
#include <fstream>
// Helper function to convert vector<int32_t> to a JSON array string
std::string vectorToJsonArray(const std::vector<int32_t>& vec) {
    std::string jsonArray = "[";
    for (size_t i = 0; i < vec.size(); ++i) {
        jsonArray += std::to_string(vec[i]);
        if (i < vec.size() - 1) {
            jsonArray += ", ";  // Add comma for all but the last element
        }
    }
    jsonArray += "]";
    return jsonArray;
}

// Helper function to convert a map<int32_t, std::string> to a JSON object as a string
std::string mapToJsonObject(const std::map<int32_t, std::string>& inner_map) {
    std::string json = "{\n";
    size_t mapSize = inner_map.size();
    size_t count = 0;

    for (const auto &pair : inner_map) {
        json += "      \"" + std::to_string(pair.first) + "\": \"" + pair.second + "\"";
        count++;
        if (count < mapSize) {
            json += ",\n";
        } else {
            json += "\n";
        }
    }

    json += "    }";
    return json;
}

// Function to save the map to a JSON file
void saveSwitchCaseResults(const std::string &filename, const std::map<std::string, std::map<int32_t, std::string>> &switch_case_map) {
    std::ofstream output_file(filename);
    if (!output_file.is_open()) {
        //std::cerr << "Error opening file for writing: " << filename << std::endl;
        return;
    }

    // Start writing the JSON file
    output_file << "[\n";

    // Iterate over the map and convert the data to JSON format
    size_t mapSize = switch_case_map.size();
    size_t count = 0;
    for (const auto &pair : switch_case_map) {
        output_file << "  {\n";
        output_file << "    \"key\": \"" << pair.first << "\",\n";
        output_file << "    \"value\": " << mapToJsonObject(pair.second) << "\n";
        count++;
        // Add closing braces, with comma if it's not the last item
        if (count < mapSize) {
            output_file << "  },\n";
        } else {
            output_file << "  }\n";
        }
    }

    output_file << "]\n";  // End of the JSON array

    output_file.close();
    //std::cout << "Data successfully written to " << filename << std::endl;
}


using namespace llvm;

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

char SymbolizeLegacyPass::ID = 0;

namespace {

Function *lastFunction;

static constexpr char kSymCtorName[] = "__sym_ctor";

bool instrumentModule(Module &M) {


  lastFunction = nullptr;

  // Find the last function in the module
  for (Function &Func : M) {
      lastFunction = &Func;
  }
  //DEBUG(errs() << "Symbolizer module instrumentation (cottontail debug version)\n");

  // Redirect calls to external functions to the corresponding wrappers and
  // rename internal functions.
  for (auto &function : M.functions()) {
    auto name = function.getName();
    if (isInterceptedFunction(function))
      function.setName(name + "_symbolized");
  }

  // Insert a constructor that initializes the runtime and any globals.
  Function *ctor;
  std::tie(ctor, std::ignore) = createSanitizerCtorAndInitFunctions(
      M, kSymCtorName, "_sym_initialize", {}, {});
  appendToGlobalCtors(M, ctor, 0);
  //printf("Symbolization Done (instrumentModule) ... size of switch_case_map = %lu\n", switch_case_map.size());
  return true;
}

bool canLower(const CallInst *CI) {
  const Function *Callee = CI->getCalledFunction();
  if (!Callee)
    return false;

  switch (Callee->getIntrinsicID()) {
  case Intrinsic::expect:
  case Intrinsic::ctpop:
  case Intrinsic::ctlz:
  case Intrinsic::cttz:
  case Intrinsic::prefetch:
  case Intrinsic::pcmarker:
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_label:
  case Intrinsic::eh_typeid_for:
  case Intrinsic::annotation:
  case Intrinsic::ptr_annotation:
  case Intrinsic::assume:
#if LLVM_VERSION_MAJOR > 11
  case Intrinsic::experimental_noalias_scope_decl:
#endif
  case Intrinsic::var_annotation:
  case Intrinsic::sqrt:
  case Intrinsic::log:
  case Intrinsic::log2:
  case Intrinsic::log10:
  case Intrinsic::exp:
  case Intrinsic::exp2:
  case Intrinsic::pow:
  case Intrinsic::sin:
  case Intrinsic::cos:
  case Intrinsic::floor:
  case Intrinsic::ceil:
  case Intrinsic::trunc:
  case Intrinsic::round:
#if LLVM_VERSION_MAJOR > 10
  case Intrinsic::roundeven:
#endif
  case Intrinsic::copysign:
#if LLVM_VERSION_MAJOR < 16
  case Intrinsic::flt_rounds:
#else
  case Intrinsic::get_rounding:
#endif
  case Intrinsic::invariant_start:
  case Intrinsic::lifetime_start:
  case Intrinsic::invariant_end:
  case Intrinsic::lifetime_end:
    return true;
  default:
    return false;
  }

  llvm_unreachable("Control cannot reach here");
}

void liftInlineAssembly(CallInst *CI) {
  // TODO When we don't have to worry about the old pass manager anymore, move
  // the initialization to the pass constructor. (Currently there are two
  // passes, but only if we're on a recent enough LLVM...)

  Function *F = CI->getFunction();
  Module *M = F->getParent();
  auto triple = M->getTargetTriple();

  std::string error;
  auto target = TargetRegistry::lookupTarget(triple, error);
  if (!target) {
    errs() << "Warning: can't get target info to lift inline assembly\n";
    return;
  }

  auto cpu = F->getFnAttribute("target-cpu").getValueAsString();
  auto features = F->getFnAttribute("target-features").getValueAsString();

  std::unique_ptr<TargetMachine> TM(
      target->createTargetMachine(triple, cpu, features, TargetOptions(), {}));
  auto subTarget = TM->getSubtargetImpl(*F);
  if (subTarget == nullptr)
    return;

  auto targetLowering = subTarget->getTargetLowering();
  if (targetLowering == nullptr)
    return;

  targetLowering->ExpandInlineAsm(CI);
}

bool instrumentFunction(Function &F) {
  auto functionName = F.getName();
  if (functionName == kSymCtorName)
    return false;

  //DEBUG(errs() << "Symbolizing function ");
  //DEBUG(errs().write_escaped(functionName) << '\n');

  SmallVector<Instruction *, 0> allInstructions;
  allInstructions.reserve(F.getInstructionCount());
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  IntrinsicLowering IL(F.getParent()->getDataLayout());
  for (auto *I : allInstructions) {
    if (auto *CI = dyn_cast<CallInst>(I)) {
      if (canLower(CI)) {
        IL.LowerIntrinsicCall(CI);
      } else if (isa<InlineAsm>(CI->getCalledOperand())) {
        liftInlineAssembly(CI);
      }
    }
  }

  allInstructions.clear();
  for (auto &I : instructions(F))
    allInstructions.push_back(&I);

  Symbolizer symbolizer(*F.getParent());
  symbolizer.symbolizeFunctionArguments(F);

  for (auto &basicBlock : F)
    symbolizer.insertBasicBlockNotification(basicBlock);

  for (auto *instPtr : allInstructions)
    symbolizer.visit(instPtr);

  symbolizer.finalizePHINodes();
  symbolizer.shortCircuitExpressionUses();

  // DEBUG(errs() << F << '\n');
  assert(!verifyFunction(F, &errs()) &&
         "SymbolizePass produced invalid bitcode");

  return true;
}

} // namespace

bool SymbolizeLegacyPass::doInitialization(Module &M) {
  return instrumentModule(M);
}

std::string getBaseFilename(const std::string& filePath) {
    // Find the last occurrence of either '/' or '\\'
    // (to handle Windows-style paths as well).
    std::size_t pos = filePath.find_last_of("/\\");
    if (pos == std::string::npos) {
        // No slash found, so the entire string is the filename
        return filePath;
    } else {
        // Return the substring after the last slash
        return filePath.substr(pos + 1);
    }
}

bool SymbolizeLegacyPass::runOnFunction(Function &F) {
  bool ret = instrumentFunction(F);
  if (switch_case_map.size() != 0) {
    //printf("Symbolization Done (runOnFunction) ... size of switch_case_map  %lu at function =%s \n",
    std::string file_name;
    if (llvm::DISubprogram *subprogram = F.getSubprogram()) {
        if (llvm::DIFile *file = subprogram->getFile()) {
            // Return only the file name without the path
            file_name = file->getFilename().str();
        }
    }
    //switch_case_map.size(), F.getName().str().c_str());
    std::string json_file_name = getBaseFilename(file_name) + "_" + F.getName().str() + ".json";
    saveSwitchCaseResults(json_file_name, switch_case_map);
    switch_case_map.clear();
  }
  return ret;
}

#if LLVM_VERSION_MAJOR >= 13

PreservedAnalyses SymbolizePass::run(Function &F, FunctionAnalysisManager &) {
  return instrumentFunction(F) ? PreservedAnalyses::none()
                               : PreservedAnalyses::all();
}

PreservedAnalyses SymbolizePass::run(Module &M, ModuleAnalysisManager &) {
  return instrumentModule(M) ? PreservedAnalyses::none()
                             : PreservedAnalyses::all();
}

#endif
