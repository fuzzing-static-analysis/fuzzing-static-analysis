#include <cstdint>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
  #include <sys/time.h>
  #include <unistd.h>
#else
  #include <io.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fstream>
#include <list>
#include <set>
#include <string>

// LLVM Includes

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Config/llvm-config.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/IRBuilder.h"
#if USE_NEW_PM
  #include "llvm/IR/PassManager.h"
  #include "llvm/Passes/PassBuilder.h"
  #include "llvm/Passes/PassPlugin.h"
#else
  #include "llvm/IR/LegacyPassManager.h"
#endif
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Verifier.h"
#include "llvm/Pass.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/FileSystem.h"

// Other includes
#include <cmath>
#include <algorithm>
#include <iostream>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <filesystem>

using namespace llvm;

namespace {

#if USE_NEW_PM
class AnalysisPass : public PassInfoMixin<AnalysisPass> {
 public:
  AnalysisPass() {
#else
class AnalysisPass : public ModulePass {
 public:
  static char ID;

  AnalysisPass() : ModulePass(ID) {
#endif
  }

#if USE_NEW_PM
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM);
#else
  bool runOnModule(Module &M) override;
#endif

 protected:
  DenseMap<BasicBlock *, uint32_t>               bb_to_cur_loc;
  DenseMap<StringRef, BasicBlock *>              entry_bb;
  DenseMap<BasicBlock *, std::vector<StringRef>> calls_in_bb;
  DenseMap<StringRef, std::vector<StringRef>>    structLinks;
  DenseMap<StringRef, std::unordered_map<int, int>> structDesc;
  // The type name is not in the memory, so create std::strign impromptu

 private:
  uint32_t travereScope(DIScope *bottom) {
    uint32_t level = 0;
    for (auto scope = bottom; !isa<DISubprogram>(scope);
         scope = scope->getScope()) {
      level += 1;
    }

    return level;
  }

  std::string typeWriter(Type *typ) {
    // Because there's no string object for the type in the memory
    // I have to build the string myself
    std::string              type_str;
    llvm::raw_string_ostream rso(type_str);
    typ->print(rso);
    return rso.str();
  }

  bool isMemCmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isMemcmp = (!FuncName.compare("memcmp") || !FuncName.compare("bcmp") ||
                     !FuncName.compare("CRYPTO_memcmp") ||
                     !FuncName.compare("OPENSSL_memcmp") ||
                     !FuncName.compare("memcmp_const_time") ||
                     !FuncName.compare("memcmpct"));
    isMemcmp &= FT->getNumParams() == 3 &&
                FT->getReturnType()->isIntegerTy(32) &&
                FT->getParamType(0)->isPointerTy() &&
                FT->getParamType(1)->isPointerTy() &&
                FT->getParamType(2)->isIntegerTy();
    return isMemcmp;
  }

  bool isStrcmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isStrcmp =
        (!FuncName.compare("strcmp") || !FuncName.compare("xmlStrcmp") ||
         !FuncName.compare("xmlStrEqual") || !FuncName.compare("g_strcmp0") ||
         !FuncName.compare("curl_strequal") ||
         !FuncName.compare("strcsequal") || !FuncName.compare("strcasecmp") ||
         !FuncName.compare("stricmp") || !FuncName.compare("ap_cstr_casecmp") ||
         !FuncName.compare("OPENSSL_strcasecmp") ||
         !FuncName.compare("xmlStrcasecmp") ||
         !FuncName.compare("g_strcasecmp") ||
         !FuncName.compare("g_ascii_strcasecmp") ||
         !FuncName.compare("Curl_strcasecompare") ||
         !FuncName.compare("Curl_safe_strcasecompare") ||
         !FuncName.compare("cmsstrcasecmp") || !FuncName.compare("strstr") ||
         !FuncName.compare("g_strstr_len") ||
         !FuncName.compare("ap_strcasestr") || !FuncName.compare("xmlStrstr") ||
         !FuncName.compare("xmlStrcasestr") ||
         !FuncName.compare("g_str_has_prefix") ||
         !FuncName.compare("g_str_has_suffix"));
    isStrcmp &=
        FT->getNumParams() == 2 && FT->getReturnType()->isIntegerTy(32) &&
        FT->getParamType(0) == FT->getParamType(1) &&
        FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext());

    return isStrcmp;
  }

  bool isStrncmp(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto FuncName = cb->getCalledFunction()->getName().str();

    bool isStrncmp =
        (!FuncName.compare("strncmp") || !FuncName.compare("xmlStrncmp") ||
         !FuncName.compare("curl_strnequal") ||
         !FuncName.compare("strncasecmp") || !FuncName.compare("strnicmp") ||
         !FuncName.compare("ap_cstr_casecmpn") ||
         !FuncName.compare("OPENSSL_strncasecmp") ||
         !FuncName.compare("xmlStrncasecmp") ||
         !FuncName.compare("g_ascii_strncasecmp") ||
         !FuncName.compare("Curl_strncasecompare") ||
         !FuncName.compare("g_strncasecmp"));
    isStrncmp &=
        FT->getNumParams() == 3 && FT->getReturnType()->isIntegerTy(32) &&
        FT->getParamType(0) == FT->getParamType(1) &&
        FT->getParamType(0) == IntegerType::getInt8PtrTy(M.getContext()) &&
        FT->getParamType(2)->isIntegerTy();
    return isStrncmp;
  }

  bool isGccStdStringStdString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();
    bool isGccStdStringStdString =
        Callee->getName().find("__is_charIT_EE7__value") != std::string::npos &&
        Callee->getName().find("St7__cxx1112basic_stringIS2_St11char_traits") !=
            std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0) == FT->getParamType(1) &&
        FT->getParamType(0)->isPointerTy();
    return isGccStdStringStdString;
  }

  bool isGccStdStringCString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isGccStdStringCString =
        Callee->getName().find(
            "St7__cxx1112basic_stringIcSt11char_"
            "traitsIcESaIcEE7compareEPK") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();
    return isGccStdStringCString;
  }

  bool isLlvmStdStringStdString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isLlvmStdStringStdString =
        Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
        Callee->getName().find("_12basic_stringI") != std::string::npos &&
        Callee->getName().find("_11char_traits") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();
    return isLlvmStdStringStdString;
  }

  bool isLlvmStdStringCString(Module &M, CallBase *cb) {
    auto FT = cb->getCalledFunction()->getFunctionType();
    auto Callee = cb->getCalledFunction();

    bool isLlvmStdStringCString =
        Callee->getName().find("_ZNSt3__1eqI") != std::string::npos &&
        Callee->getName().find("_12basic_stringI") != std::string::npos &&
        FT->getNumParams() >= 2 && FT->getParamType(0)->isPointerTy() &&
        FT->getParamType(1)->isPointerTy();

    return isLlvmStdStringCString;
  }

  bool isLLVMIntrinsicFn(StringRef &n) {
    // Not interested in these LLVM's functions
    if (n.startswith("llvm.")) {
      return true;
    } else {
      return false;
    }
  }

  bool isMemorySensitiveFn(StringRef &n) {
    if (n.equals("write") || n.equals("read") || n.equals("fgets") ||
        n.equals("memcmp") || n.equals("memcpy") || n.equals("mempcpy") ||
        n.equals("memmove") || n.equals("memset") || n.equals("memchr") ||
        n.equals("memrchr") || n.equals("memmem") || n.equals("bzero") ||
        n.equals("explicit_bzero") || n.equals("bcmp") || n.equals("strchr") ||
        n.equals("strrchr") || n.equals("strcasecmp") || n.equals("strncat") ||
        n.equals("strerror") || n.equals("strncasecmp") || n.equals("strcat") ||
        n.equals("strcmp") || n.equals("strspn") || n.equals("strncmp") ||
        n.equals("strcpy") || n.equals("strncpy") || n.equals("strcoll") ||
        n.equals("stpcpy") || n.equals("strdup") || n.equals("strlen") ||
        n.equals("strxfrm") || n.equals("strtok") || n.equals("strnlen") ||
        n.equals("strstr") || n.equals("strcasestr") || n.equals("strscpn") ||
        n.equals("strpbrk") || n.equals("atoi") || n.equals("atol") ||
        n.equals("atoll") || n.equals("wcslen") || n.equals("wcscpy") ||
        n.equals("wcscmp")) {
      return true;
    } else {
      return false;
    }
  }

  bool isMallocFn(StringRef &n) {
    if (n.equals("malloc") || n.equals("calloc") || n.equals("realloc") ||
        n.equals("reallocarray") || n.equals("memalign") ||
        n.equals("__libc_memalign") || n.equals("aligned_alloc") ||
        n.equals("posix_memalign") || n.equals("valloc") ||
        n.equals("pvalloc") || n.equals("mmap")) {
      return true;
    } else {
      return false;
    }
  }

  bool isFreeFn(StringRef &n) {
    if (n.equals("free") || n.equals("cfree") || n.equals("munmap")) {
      return true;
    } else {
      return false;
    }
  }

  bool isCppNewFn(StringRef &n) {
    // operator new[](unsigned long)
    // operator new[](unsigned long, std::nothrow_t const&)
    // operator new[](unsigned long, std::align_val_t)
    // operator new[](unsigned long, std::align_val_t, std::nothrow_t const&)
    // operator new(unsigned long)
    // operator new(unsigned long, std::nothrow_t const&)
    // operator new(unsigned long, std::align_val_t)
    // operator new(unsigned long, std::align_val_t, std::nothrow_t const&)

    if (n.equals("_Znam") || n.equals("_ZnamRKSt9nothrow_t") ||
        n.equals("_ZnamSt11align_val_t") ||
        n.equals("_ZnamSt11align_val_tRKSt9nothrow_t") || n.equals("_Znwm") ||
        n.equals("_ZnwmRKSt9nothrow_t") || n.equals("_ZnwmSt11align_val_t") ||
        n.equals("_ZnwmSt11align_val_tRKSt9nothrow_t")) {
      return true;
    } else {
      return false;
    }
  }

  bool isCppDelete(StringRef &n) {
    // operator delete[](void*)
    // operator delete[](void*, unsigned long)
    // operator delete[](void*, unsigned long, std::align_val_t)
    // operator delete[](void*, std::nothrow_t const&)
    // operator delete[](void*, std::align_val_t)
    // operator delete[](void*, std::align_val_t, std::nothrow_t const&)
    // operator delete(void*)
    // operator delete(void*, unsigned long)
    // operator delete(void*, unsigned long, std::align_val_t)
    // operator delete(void*, std::nothrow_t const&)
    // operator delete(void*, std::align_val_t)
    // operator delete(void*, std::align_val_t, std::nothrow_t const&)

    if (n.equals("_ZdaPv") || n.equals("_ZdaPvm") ||
        n.equals("_ZdaPvmSt11align_val_t") ||
        n.equals("_ZdaPvRKSt9nothrow_t") || n.equals("_ZdaPvSt11align_val_t") ||
        n.equals("_ZdaPvSt11align_val_tRKSt9nothrow_t") || n.equals("_ZdlPv") ||
        n.equals("_ZdlPvm") || n.equals("_ZdlPvmSt11align_val_t") ||
        n.equals("_ZdlPvRKSt9nothrow_t") || n.equals("_ZdlPvSt11align_val_t") ||
        n.equals("_ZdlPvSt11align_val_tRKSt9nothrow_t")

    ) {
      return true;
    } else {
      return false;
    }
  }
};

}  // namespace

inline bool file_exist(const std::string &name) {
  std::ifstream f(name.c_str());
  return f.good();
}

#if USE_NEW_PM
extern "C" ::llvm::PassPluginLibraryInfo LLVM_ATTRIBUTE_WEAK
llvmGetPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "AnalysisPass", "v0.1",
          /* lambda to insert our pass into the pass pipeline. */
          [](PassBuilder &PB) {

  #if LLVM_VERSION_MAJOR <= 13
            using OptimizationLevel = typename PassBuilder::OptimizationLevel;
  #endif
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel OL) {
                  MPM.addPass(AnalysisPass());
                });
          }};
}
#else
char AnalysisPass::ID = 0;
#endif

#if USE_NEW_PM
PreservedAnalyses AnalysisPass::run(Module &M, ModuleAnalysisManager &MAM) {
#else
bool AnalysisPass::runOnModule(Module &M) {

#endif

  std::string            relFilename = M.getSourceFileName();
  llvm::SmallString<128> FilenameVec = StringRef(relFilename);
  llvm::SmallString<128> RealPath;
  llvm::sys::fs::real_path(FilenameVec, RealPath);
  std::filesystem::path fp{std::string(RealPath)};
  std::string           genericFilePath = fp.generic_string();

  std::replace(genericFilePath.begin(), genericFilePath.end(), '/', '#');

  /*
    std::ifstream ifs;
    ifs.open("/out/whitelist.txt");

    if (ifs.fail()) { abort(); }
    std::string              srcfile;
    std::vector<std::string> srcList;
    while (ifs >> srcfile) {
      srcList.push_back(srcfile);
    }

    bool run = false;

    for (std::string S : srcList) {
      if (S == Filename) {
        outs() << "Accept " << Filename << "\n";
        run = true;
      }
    }
  */
  bool run = true;

  bool done_already = file_exist("/out/." + genericFilePath + ".json");
  if (done_already) {
    run = false;
  } else {
    std::ofstream out_lock("/out/." + genericFilePath + ".json");
  }

  if (run) {
    outs() << "Analysis on " + genericFilePath << "\n";
    LLVMContext &Ctx = M.getContext();
    auto         moduleName = M.getName().str();
    // printf("Hello\n");
    for (auto ST : M.getIdentifiedStructTypes()) {
      std::unordered_map<int, int> types;
      for (auto T : ST->elements()) {
        types[T->getTypeID()] += 1;
        auto ty = T;
        while (true) {
          // Recursive
          if (ty->isPointerTy()) {
            ty = ty->getPointerElementType();
            continue;
          } else if (ty->isStructTy()) {
            structLinks[ST->getStructName()].push_back(ty->getStructName());
          }
          break;
        }
      }

      structDesc[ST->getStructName()] = types;
    }
    nlohmann::json res;

    for (auto &F : M) {

      if (F.isDeclaration()) {
        continue;
      }

      DenseMap<StringRef, u_int32_t>            APIcalls;
      DenseMap<StringRef, uint32_t>             heapAPIs;
      DenseMap<StringRef, uint32_t>             memoryAPIs;
      std::unordered_map<uint32_t, uint32_t>    nestedLevel;
      std::unordered_map<uint32_t, uint32_t>    cmpGlobals;
      std::unordered_map<uint32_t, uint32_t>    cmpNonZeros;
      DenseMap<StringRef, uint32_t>             structWrites;
      std::unordered_map<std::string, uint32_t> structArgs;
      std::unordered_map<std::string, uint32_t> cmpTypes;
      std::unordered_map<std::string, uint32_t> callArgTypes;
      std::unordered_map<std::string, uint32_t> storeTypes;
      std::unordered_map<std::string, uint32_t> loadTypes;
      std::unordered_map<std::string, uint32_t> allocaTypes;
      std::unordered_map<std::string, uint32_t> cmpComplexity;

      unsigned bb_cnt = 0;
      unsigned inst_cnt = 0;
      unsigned edges_cnt = 0;

      unsigned call_cnt = 0;
      unsigned cmp_cnt = 0;
      unsigned load_cnt = 0;
      unsigned store_cnt = 0;
      unsigned alloca_cnt = 0;
      unsigned branch_cnt = 0;
      unsigned binary_op_cnt = 0;

      entry_bb[F.getName()] = &F.getEntryBlock();
      for (auto &BB : F) {
        bb_to_cur_loc[&BB] = bb_cnt;
        bb_cnt++;
        for (auto &IN : BB) {
          /// Check data types

          auto meta = IN.getMetadata(0);
          if (meta) {
            DILocation *diloc = nullptr;
            if ((diloc = dyn_cast<DILocation>(meta))) {
              auto     scope = diloc->getScope();
              uint32_t nested_level = travereScope(scope);
              nestedLevel[nested_level] += 1;
            }
          }

          CallBase       *callBase = nullptr;
          CmpInst        *cmpInst = nullptr;
          LoadInst       *loadInst = nullptr;
          StoreInst      *storeInst = nullptr;
          AllocaInst     *allocaInst = nullptr;
          BranchInst     *branchInst = nullptr;
          BinaryOperator *binaryOp = nullptr;

          if ((binaryOp = dyn_cast<BinaryOperator>(&IN))) {
            binary_op_cnt++;
          } else if ((branchInst = dyn_cast<BranchInst>(&IN))) {
            branch_cnt++;
          } else if ((callBase = dyn_cast<CallBase>(&IN))) {
            // What type of call is this?
            auto F = callBase->getCalledFunction();
            if (F) {
              StringRef name = F->getName();
              if (isLLVMIntrinsicFn(name)) {
                // just ignore
                continue;
              }
              APIcalls[name]++;
              call_cnt++;

              calls_in_bb[&BB].push_back(name);
              // Check memory related calls
              if (isMallocFn(name)) {
                heapAPIs["malloc"]++;
              } else if (isFreeFn(name)) {
                heapAPIs["free"]++;
              } else if (isCppNewFn(name)) {
                heapAPIs["new"]++;
              } else if (isCppDelete(name)) {
                heapAPIs["delete"]++;
              }

              if (isMemorySensitiveFn(name)) { 
                memoryAPIs[name]++; 
              }

              if (isMemCmp(M, callBase)) {
                cmpComplexity["mem cmp"]++;
              } else if (isStrcmp(M, callBase) || isStrncmp(M, callBase) ||
                         isGccStdStringCString(M, callBase) ||
                         isGccStdStringStdString(M, callBase) ||
                         isLlvmStdStringCString(M, callBase) ||
                         isLlvmStdStringStdString(M, callBase)) {
                cmpComplexity["str cmp"]++;
              }

              for (auto arg = F->arg_begin(); arg != F->arg_end(); arg++) {
                auto        arg_ty = arg->getType();
                std::string type_str = typeWriter(arg_ty);
                callArgTypes[type_str]++;

                auto ty = arg_ty;
                while (true) {
                  // recursive
                  if (ty->isPointerTy()) {
                    ty = ty->getPointerElementType();
                    continue;
                  } else if (ty->isStructTy()) {
                    structArgs[type_str]++;
                  }
                  break;
                }
              }
            }
          } else if ((cmpInst = dyn_cast<CmpInst>(&IN))) {
            FCmpInst *fcmp = nullptr;
            ICmpInst *icmp = nullptr;

            if ((icmp = dyn_cast<ICmpInst>(cmpInst))) {
              cmpComplexity["int cmp"]++;
            } else if ((fcmp = dyn_cast<FCmpInst>(cmpInst))) {
              cmpComplexity["float cmp"]++;
            }
            auto typ = cmpInst->getOperand(0)->getType();

            auto op0 = cmpInst->getOperand(0);
            auto op1 = cmpInst->getOperand(1);
            uint32_t num_constants = 0;
            uint32_t non_zero_constants = 0;

            Constant *c1 = nullptr;
            Constant *c2 = nullptr;

            if ((c1 = dyn_cast<Constant>(op0))) {
              if (!c1->isZeroValue())  {
                non_zero_constants++;
              }
              num_constants++;
            }

            if ((c2 = dyn_cast<Constant>(op1))) {
              if (c2->isZeroValue())  {
                non_zero_constants++;
              }
              num_constants++;
            }

            cmpGlobals[num_constants]++;
            cmpNonZeros[num_constants]++;
            cmpTypes[typeWriter(typ)]++;
            cmp_cnt++;
          } else if ((loadInst = dyn_cast<LoadInst>(&IN))) {
            auto typ = loadInst->getType();
            loadTypes[typeWriter(typ)]++;
            load_cnt++;
          } else if ((storeInst = dyn_cast<StoreInst>(&IN))) {
            auto typ = storeInst->getValueOperand()->getType();
            storeTypes[typeWriter(typ)]++;
            // Here check writes into structs
            // check where storeInst stores into
            auto               op = storeInst->getPointerOperand();
            GetElementPtrInst *gep = nullptr;
            if ((gep = dyn_cast<GetElementPtrInst>(op))) {
              // If this is a gep?
              auto typ = gep->getSourceElementType();

              if (typ->isStructTy()) { structWrites[typ->getStructName()]++; }
            }

            store_cnt++;
          } else if ((allocaInst = dyn_cast<AllocaInst>(&IN))) {
            auto typ = allocaInst->getAllocatedType();
            allocaTypes[typeWriter(typ)]++;
            alloca_cnt++;
          }

          inst_cnt++;
        }

        auto term = BB.getTerminator();
        edges_cnt += term->getNumSuccessors();

        // Dump everything in this Fn
      }

      std::string fnname = std::string(F.getName());
      if (bb_cnt) { res[fnname]["# BBs"] = bb_cnt; }

      if (inst_cnt) { res[fnname]["# insts"] = inst_cnt; }

      if (edges_cnt) { res[fnname]["# edges"] = edges_cnt; }

      if (binary_op_cnt) { res[fnname]["# binaryOp"] = binary_op_cnt; }

      if (call_cnt) { res[fnname]["# call"] = call_cnt; }

      if (cmp_cnt) { res[fnname]["# cmp"] = cmp_cnt; }

      if (load_cnt) { res[fnname]["# load"] = load_cnt; }

      if (store_cnt) { res[fnname]["# store"] = store_cnt; }

      if (alloca_cnt) { res[fnname]["# alloca"] = alloca_cnt; }

      if (branch_cnt) { res[fnname]["# branch"] = branch_cnt; }

      res[fnname]["ABC metric"] =
          sqrt(alloca_cnt * alloca_cnt + branch_cnt * branch_cnt +
               call_cnt * call_cnt);
      res[fnname]["cyclomatic"] = edges_cnt - bb_cnt + 2;

      // outs() << "APIs:\n";
      for (auto record = APIcalls.begin(); record != APIcalls.end(); record++) {
        auto key = record->getFirst();
        if (!isLLVMIntrinsicFn(key)) {
          res[fnname]["AP"][std::string(key)] = APIcalls[key];
          // outs() << key << " " << APIcalls[key] << "\n";
        }
      }
      // outs() << "\n";

      // outs() << "memoryAPIs:\n";
      for (auto record = heapAPIs.begin(); record != heapAPIs.end(); record++) {
        auto key = record->getFirst();
        res[fnname]["h AP"][std::string(key)] = heapAPIs[key];
        // outs() << key << " " << heapAPIs[key] << "\n";
      }
      // outs() << "\n";

      for (auto record = memoryAPIs.begin(); record != memoryAPIs.end();
           record++) {
        auto key = record->getFirst();
        res[fnname]["m AP"][std::string(key)] = memoryAPIs[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = nestedLevel.begin(); record != nestedLevel.end();
           record++) {
        auto key = record->first;
        res[fnname]["ne lv"][std::to_string(key)] = nestedLevel[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = cmpGlobals.begin(); record != cmpGlobals.end();
           record++) {
        auto key = record->first;
        res[fnname]["cm gl"][std::to_string(key)] = cmpGlobals[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      for (auto record = cmpNonZeros.begin(); record != cmpNonZeros.end();
           record++) {
        auto key = record->first;
        res[fnname]["cm nz"][std::to_string(key)] = cmpNonZeros[key];
        // outs() << key << " " << memoryAPIs[key] << "\n";
      }

      // outs() << "writesIntoStructs:\n";
      for (auto record = structWrites.begin(); record != structWrites.end();
           record++) {
        auto key = record->getFirst();
        // Some are nameless struct
        res[fnname]["wr st"][std::string(key)] = structWrites[key];
        // outs() << key << " " << structWrites[key] << "\n";
      }
      // outs() << "\n";

      // outs() << "StructsInArgs:\n";
      for (auto record = structArgs.begin(); record != structArgs.end();
           record++) {
        auto key = record->first;
        res[fnname]["str arg"][std::string(key)] = record->second;
        // outs() << key << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "CmpTypes:\n";
      for (auto record = cmpTypes.begin(); record != cmpTypes.end(); record++) {
        res[fnname]["cm ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      for (auto record = cmpComplexity.begin(); record != cmpComplexity.end();
           record++) {
        res[fnname]["cm cm"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }

      // outs() << "CallArgTypes:\n";
      for (auto record = callArgTypes.begin(); record != callArgTypes.end();
           record++) {
        res[fnname]["ar ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "storeTypes:\n";
      for (auto record = storeTypes.begin(); record != storeTypes.end();
           record++) {
        res[fnname]["st ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "loadTypes:\n";
      for (auto record = loadTypes.begin(); record != loadTypes.end();
           record++) {
        res[fnname]["l ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      // outs() << "allocaTypes:\n";
      for (auto record = allocaTypes.begin(); record != allocaTypes.end();
           record++) {
        res[fnname]["al ty"][record->first] = record->second;
        // outs() << record->first << " " << record->second << "\n";
      }
      // outs() << "\n";

      if (getenv("ANALYSIS_OUTPUT_PATH")) {
        if (std::ofstream(getenv("ANALYSIS_OUTPUT_PATH") + std::string("/") +
                          genericFilePath + ".json")
            << res << "\n") {
        } else {
          abort();
        }
      } else {
        errs() << "output path not set!"
               << "\n";
      }
    }

    nlohmann::json struct_links;
    // outs() << "StructLinks:\n";
    for (auto record = structLinks.begin(); record != structLinks.end();
         record++) {
      StringRef key = record->getFirst();
      // outs() << "struct: " << key << "\t";
      std::vector<std::string> links{};
      // outs() << "links: ";
      for (auto item = structLinks[key].begin(); item != structLinks[key].end();
           item++) {
        links.push_back(std::string(*item));
        // outs() << *item << " ";
      }
      struct_links[moduleName][std::string(key)]["lks"] = links;
      // outs() << "\n";
    }

    for (auto record = structDesc.begin(); record != structDesc.end(); record++) {
      auto key = record->getFirst();
      struct_links[moduleName][std::string(key)]["desc"] = record->second;
    }

    // outs() << "\n";

    if (getenv("ANALYSIS_OUTPUT_PATH")) {
      if (std::ofstream(getenv("ANALYSIS_OUTPUT_PATH") + std::string("/") +
                        genericFilePath + ".lks")
          << struct_links << "\n") {
      } else {
        abort();
      }
    } else {
      errs() << "output path not set!"
             << "\n";
    }

    nlohmann::json cfg;

    for (auto record = bb_to_cur_loc.begin(); record != bb_to_cur_loc.end();
         record++) {
      auto        current_bb = record->getFirst();
      auto        loc = record->getSecond();
      Function   *calling_func = current_bb->getParent();
      std::string func_name = std::string("");

      if (calling_func) {
        func_name = std::string(calling_func->getName());
        // outs() << "Function name: " << calling_func->getName() << "\n";
      }

      std::vector<uint32_t> outgoing;
      for (auto bb_successor = succ_begin(current_bb);
           bb_successor != succ_end(current_bb); bb_successor++) {
        outgoing.push_back(bb_to_cur_loc[*bb_successor]);
      }
      cfg["edges"][func_name][loc] = outgoing;
    }

    for (auto record = calls_in_bb.begin(); record != calls_in_bb.end();
         record++) {
      auto        current_bb = record->getFirst();
      auto        loc = bb_to_cur_loc[current_bb];
      Function   *calling_func = current_bb->getParent();
      std::string func_name = std::string("");

      if (calling_func) {
        func_name = std::string(calling_func->getName());
        // outs() << "Function name: " << calling_func->getName() << "\n";
      }

      std::vector<std::string> outgoing_funcs;
      for (auto &item : record->getSecond()) {
        outgoing_funcs.push_back(std::string(item));
      }
      if (!outgoing_funcs.empty()) {
        cfg["calls"][func_name][std::to_string(loc)] = outgoing_funcs;
      }
    }

    for (auto record = entry_bb.begin(); record != entry_bb.end(); record++) {
      cfg["entries"][std::string(record->getFirst())] =
          bb_to_cur_loc[record->getSecond()];
    }

    if (getenv("ANALYSIS_OUTPUT_PATH")) {
      if (std::ofstream(getenv("ANALYSIS_OUTPUT_PATH") + std::string("/") +
                        genericFilePath + ".cfg")
          << cfg << "\n") {
      } else {
        abort();
      }

    } else {
      errs() << "output path not set!"
             << "\n";
    }
  }

#if USE_NEW_PM
  auto PA = PreservedAnalyses::all();
  return PA;
#else
  return true;
#endif
}
