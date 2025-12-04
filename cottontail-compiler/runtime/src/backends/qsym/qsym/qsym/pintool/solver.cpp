#include <set>
#include <byteswap.h>
#include "solver.h"

#include "GenericTree.h" // for tree maintainer
#include "call_stack_manager.h"

namespace qsym {
extern CallStackManager g_call_stack_manager;
extern GenericTree<std::string> tree;
auto currentNode = tree.getRootPtr();
std::vector <std::string> g_cov_call_stack;
extern bool is_saved;
namespace {

const uint64_t kUsToS = 1000000;
const int kSessionIdLength = 32;
const unsigned kSolverTimeout = 10000; // 10 seconds
int total_solving = 0;
int invalid_solving = 0;


std::string toString6digit(INT32 val) {
  char buf[6 + 1]; // ndigit + 1
  snprintf(buf, 7, "%06d", val);
  buf[6] = '\0';
  return std::string(buf);
}

uint64_t getTimeStamp() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * kUsToS + tv.tv_usec;
}

void parseConstSym(ExprRef e, Kind &op, ExprRef& expr_sym, ExprRef& expr_const) {
  for (INT32 i = 0; i < 2; i++) {
    expr_sym = e->getChild(i);
    expr_const = e->getChild(1 - i);
    if (!isConstant(expr_sym)
        && isConstant(expr_const)) {
      op = i == 0 ? e->kind() : swapKind(e->kind());
      return;
    }
  }
  UNREACHABLE();
}

void getCanonicalExpr(ExprRef e,
    ExprRef* canonical,
    llvm::APInt* adjustment=NULL) {
  ExprRef first = NULL;
  ExprRef second = NULL;
  // e == Const + Sym --> canonical == Sym
  switch (e->kind()) {
    // TODO: handle Sub
    case Add:
      first = e->getFirstChild();
      second = e->getSecondChild();
      if (isConstant(first)) {
        *canonical = second;
        if (adjustment != NULL)
          *adjustment =
            static_pointer_cast<ConstantExpr>(first)->value();
        return;
      case Sub:
        // C_0 - Sym
        first = e->getFirstChild();
        second = e->getSecondChild();
        // XXX: need to handle reference count
        if (isConstant(first)) {
          *canonical = g_expr_builder->createNeg(second);
          if (adjustment != NULL)
            *adjustment = static_pointer_cast<ConstantExpr>(first)->value();
          return;
        }
      }
    default:
      break;
  }
  if (adjustment != NULL)
    *adjustment = llvm::APInt(e->bits(), 0);
  *canonical = e;
}

inline bool isEqual(ExprRef e, bool taken) {
  return (e->kind() == Equal && taken) ||
    (e->kind() == Distinct && !taken);
}

int fileExistsAndNotEmpty(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);

    if (file) {
        // Check if the file size is greater than 0
        return file.tellg() > 0 ? 1 : 0;
    }

    // File does not exist or could not be opened
    return 0;
}

} // namespace

Solver::Solver(
    const std::string input_file,
    const std::string out_dir,
    const std::string bitmap)
  : input_file_(input_file)
  , inputs_()
  , out_dir_(out_dir)
  , context_(*g_z3_context)
  , solver_(z3::solver(context_, "QF_BV"))
  , num_generated_(0)
  , trace_(bitmap)
  , last_interested_(false)
  , syncing_(false)
  , start_time_(getTimeStamp())
  , solving_time_(0)
  , last_pc_(0)
  , dep_forest_()
{
  // Set timeout for solver
  z3::params p(context_);
  p.set(":timeout", kSolverTimeout);
  solver_.set(p);

  checkOutDir();
  readInput();
  // store input bytes
  std::vector<UINT8> values = inputs_;
  tree.rootNodePtr->taken = 1;
  tree.rootNodePtr->branch_id = -1;
  tree.rootNodePtr->call_stack_size = 0;
  std::string filename = "global-tree.json";
  if (tree.getDepth() == 1 && fileExistsAndNotEmpty(filename)) {
    tree.loadFromJsonFile(filename);
  }

}

void Solver::push() {
  solver_.push();
}

void Solver::reset() {
  solver_.reset();
}

void Solver::pop() {
  solver_.pop();
}

void Solver::add(z3::expr expr) {
  if (!expr.is_const())
    solver_.add(expr.simplify());
}

z3::check_result Solver::check() {
  uint64_t before = getTimeStamp();
  z3::check_result res;
  LOG_STAT(
      "SMT: { \"solving_time\": " + decstr(solving_time_) + ", "
      + "\"total_time\": " + decstr(before - start_time_) + " }\n");
  try {
    res = solver_.check();
  }
  catch(z3::exception e) {
    // https://github.com/Z3Prover/z3/issues/419
    // timeout can cause exception
    res = z3::unknown;
  }
  uint64_t cur = getTimeStamp();
  uint64_t elapsed = cur - before;
  solving_time_ += elapsed;
  LOG_STAT("SMT: { \"solving_time\": " + decstr(solving_time_) + " }\n"); // THX
  return res;
}

bool Solver::checkAndSave(const std::string& postfix) {
  if (check() == z3::sat) {
    saveValues(postfix);
    return true;
  }
  else {
    if (check() == z3::unknown) LOG_STAT("UNKNOWN PC!!!");
    return false;
  }
}

bool Solver::checkOnly(const std::string& postfix) {
  if (check() == z3::sat) {
    return true;
  }
  else {
    return false;
  }
}

std::optional<uint64_t> extractConstantValueAsUInt(const z3::expr &e) {
    if (e.is_app()) { // Check if the expression has children
        // Iterate over each child of the expression
        for (unsigned i = 0; i < e.num_args(); ++i) {
            z3::expr child = e.arg(i);
            // Check if the child is a numeral (constant)
            if (child.is_numeral()) {
                // Use the Z3 C API to get the numeral as a string
                std::string value_str = Z3_get_numeral_string(e.ctx(), child);
                try {
                    // Convert the string to uint64_t
                    return std::stoull(value_str, nullptr, 0);  // Use base 0 to auto-detect hex or decimal
                } catch (const std::invalid_argument& ex) {
                    std::cerr << "Invalid argument for conversion: " << ex.what() << "\n";
                } catch (const std::out_of_range& ex) {
                    std::cerr << "Value out of range: " << ex.what() << "\n";
                }
            }
        }
    }

    // Return an empty optional if no constant was found
    return std::nullopt;
}

void printExpressionChildren(const z3::expr &e) {
    if (e.is_app()) { // Check if the expression is an application (i.e., has children)

        // Iterate over each child (argument) of the expression
        for (unsigned i = 0; i < e.num_args(); ++i) {
            z3::expr child = e.arg(i);
        }
    } else {
        std::cout << "The expression has no children (it is likely a constant or variable).\n";
    }
}

json getValuesByKey(const std::string& fileName, const std::string& key) {
    // Open the JSON file
    std::ifstream inputFile(fileName);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open file: " + fileName);
    }

    // Parse the JSON file
    json data;
    inputFile >> data;

    // Search for the key
    for (const auto& entry : data) {
        if (entry.contains("key") && entry["key"] == key) {
            return entry["value"];
        }
    }

    // If the key is not found, return an empty JSON object
    return json({});
}

std::string findValueByKey(const json& valueMap, int key) {
    // Convert the integer key to a string to match JSON keys
    std::string keyString = std::to_string(key);

    // Check if the key exists in the JSON object
    if (valueMap.contains(keyString)) {
        return valueMap.at(keyString);
    }

    throw std::runtime_error("Key not found in JSON object");
}

std::string extractBeforeFirstNumber(const std::string& input) {
    // Find the first character that is a digit
    auto it = std::find_if(input.begin(), input.end(), [](char c) {
        return std::isdigit(static_cast<unsigned char>(c));
    });

    // Calculate the position of the first digit
    size_t pos = std::distance(input.begin(), it);

    // Extract the substring before the first digit
    std::string result = input.substr(0, pos);

    // Remove the trailing underscore, if present
    if (!result.empty() && result.back() == '_') {
        result.pop_back();
    }

    return result;
}

bool evaluateSingleExpression(z3::expr org_expr, z3::expr sym_expr, z3::expr con_expr){
    z3::context &ctx = org_expr.ctx();
    z3::expr before_substitute(ctx), after_substitute(ctx);
    before_substitute = sym_expr;
    after_substitute = con_expr;

    Z3_ast from[] = { before_substitute };
    Z3_ast to [] = { after_substitute };
    z3::expr new_expr(ctx);
    new_expr = z3::to_expr(ctx, Z3_substitute(ctx, org_expr, 1, from, to));

    // Check if the simplified expression is a boolean or numeral
    if (new_expr.is_bool()) {
        return new_expr.is_true();
    } else if (new_expr.is_numeral()) {
        std::string valueStr = Z3_get_numeral_string(ctx, new_expr);
        try {
            uint64_t value = std::stoull(valueStr, nullptr, 0);
            return value != 0;
        } catch (...) {
            std::cerr << "Error converting numeral to uint64_t: " << valueStr << "\n";
            return false;
        }
    } else {
        std::cerr << "Unexpected expression type after simplification.\n";
        return false;
    }

    //return new_expr;
}

/**
 * Evaluate a symbolic expression by substituting symbolic variables with values
 * from the input and checking if the result is true or false.
 *
 * @param expr The symbolic Z3 expression.
 * @param input A vector of input bytes from the user.
 * @return true if the expression evaluates to true, false otherwise.
 */
bool evaluateSymbolicExpression(z3::expr expr, const std::vector<uint8_t> &input) {
    z3::context &ctx = expr.ctx();

    // Collect all the symbols (variables) in the expression
    std::unordered_map<std::string, z3::expr> symbolMap;
    std::unordered_map<std::string, z3::expr> symbolConMap;


    // Traverse the expression to find variables
    std::function<void(const z3::expr &)> traverse = [&](const z3::expr &e) {
        if (e.is_const()) {
            // Extract the symbol name
            z3::symbol sym = e.decl().name();
            std::string symbolName;

            if (sym.kind() == Z3_STRING_SYMBOL) {
                symbolName = sym.str();
            } else if (sym.kind() == Z3_INT_SYMBOL) {
                symbolName = "k!" + std::to_string(sym.to_int());
            } else {
                return; // Skip unknown symbols
            }
            if (symbolName.find("k!") == 0) { // only store the symbol starting with k
              symbolMap.emplace(symbolName, e);
            }
        }

        // Traverse arguments recursively
        for (unsigned i = 0; i < e.num_args(); ++i) {
            traverse(e.arg(i));
        }
    };

    traverse(expr);

    // Prepare substitutions
    std::vector<Z3_ast> fromVec, toVec;

    for (const auto &pair : symbolMap) {
        const std::string &symbolName = pair.first;
        const z3::expr &variable = pair.second;

        // Parse the index from the symbol name (e.g., "k!0")
        size_t index = 0;
        try {
            if (symbolName.find("k!") == 0) {
                index = std::stoul(symbolName.substr(2));
            } else {
                continue; // Skip invalid symbols
            }
        } catch (...) {
            continue; // Skip parsing errors
        }

        if (index < input.size()) {
            fromVec.push_back(variable);
            // Create a concrete value with the same bit-width as the variable
            unsigned bv_size = variable.get_sort().bv_size();
            z3::expr concreteValue = ctx.bv_val(input[index], bv_size);
            toVec.push_back(concreteValue);
            symbolConMap.emplace(symbolName, concreteValue);
        } else {
            // Index is out of bounds; skip this variable
            assert(0 && "Index is out of bounds when evalatuing symbolic exression");
            continue;
        }
    }

    if (fromVec.empty()) {
        std::cerr << "No valid substitutions found.\n";
        return false;
    }

    // Substitute using Z3_substitute
    bool result;
    for (auto pair : symbolMap){
      result = evaluateSingleExpression(expr, pair.second, symbolConMap.at(pair.first));
    }

    return result;
}

bool getEnvBool(const char* varName) {
    const char* value = getenv(varName);
    if (value == nullptr) return false; // If not set, treat as false.

    std::string strValue(value);
    std::transform(strValue.begin(), strValue.end(), strValue.begin(), ::tolower);

    // Check for truthy values
    return (strValue == "1" || strValue == "true" || strValue == "yes" || strValue == "YES");
}


void Solver::addJcc(ExprRef e, bool taken, ADDRINT pc, char* name, char* op_name, int if_branch_type) {
  // Save the last instruction pointer for debugging
  last_pc_ = pc;

  if (e->isConcrete()) {
    return;
  }

  // if e == Bool(true), then ignore
  if (e->kind() == Bool) {
    assert(!(castAs<BoolExpr>(e)->value()  ^ taken));
    return;
  }

  assert(isRelational(e.get()));

  // check duplication before really solving something,
  // some can be handled by range based constraint solving
  bool is_interesting;
  bool use_cottontail_map = getEnvBool("USE_ESCT");
  bool use_no_map = getEnvBool("USE_NO_MAP");

  if (!use_cottontail_map) {
    if (pc == 0) {
      // If addJcc() is called by special case, then rely on last_interested_
      //std::cout << "||||| THX: here is a branch uninteresting \n";
      is_interesting = last_interested_;
    }
    else
      is_interesting = isInterestingJcc(e, taken, pc);
  } else {
    is_interesting = 1;
  }

  if (use_no_map) is_interesting = 1;

  // if this is a switch statement
  assert(op_name && "op_name is null");

  // some notes
  // taken = 1 for root, fake, switch (head) node
  // branch = -1 for root, fake, switch (head) node
  // branch = 0 for if-else (non-switch) branch node
  // branch = x for switch-case branch node
  // creat the tree nodes
  int g_manager_size = g_call_stack_manager.call_stack_.size();
  int g_cov_size = g_cov_call_stack.size();
  bool con_taken = !evaluateSymbolicExpression(e.get()->toZ3Expr(), inputs_);
  bool unvisisted = 0;
  bool show_switch_tree = 0; // for debug only
  bool show_non_switch_tree = 0; // for debug only

  if (strcmp(op_name, "switch") == 0){
    auto currentNode = tree.nodeExists(name, g_manager_size);
    if (!currentNode) {
      int cnt_before_add = tree.countTreeNodes();
      //LOG_STAT("Handle SWITCH case: creat two child nodes?\n");
      // get cases values:
      std::string file_name = extractBeforeFirstNumber(name);
      const std::string filePath = std::string("./") + file_name + std::string(".json");
      json result = getValuesByKey(filePath, name);
      std::optional<long unsigned int> con_value = extractConstantValueAsUInt(e.get()->toZ3Expr());
      
      if (g_cov_size == 0){
        if (g_manager_size == 0){
          //LOG_STAT("SWITCH: Add the first level nodes\n");
          tree.addChildToNode("root", name, -1, 0, 1, 1, -1, g_manager_size);
          for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(name, it.value(), -1, 0, 1, 0, std::stoi(it.key()), g_manager_size);
          }
          is_saved = 0;
          if (show_switch_tree) std::cout << tree << "\n";
        }
        if (g_manager_size == 1){
          //LOG_STAT ("SWITCH: Encounter a function all\n");
          // need to add multipule nodes based on the case value
          tree.addChildToNode("root", name, -1, 0, 1,  1, -1, g_manager_size - 1);
          g_cov_call_stack.push_back(name);
          //TODO replace the name with the case statement location
          for (auto it = result.begin(); it != result.end(); ++it) {
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], it.value(), -1, g_manager_size - 1, 1, 0, 
                              std::stoi(it.key()), g_manager_size);
          }
          is_saved = 0;
          if (show_switch_tree) std::cout << tree << "\n";
        }
        if (g_manager_size >= 2){
          //LOG_STAT ("SWITCH: Handling Direct Function Calls\n");
          std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
          if (!tree.nodeExists(fake_func_name, 1)) {
           tree.addChildToNode("root", fake_func_name, -1, 0, 1, 1, -1, 1);
            g_cov_call_stack.push_back(fake_func_name);
          } else {
            g_cov_call_stack.push_back(fake_func_name);
          }

          for (int i = 0; i < g_manager_size - g_cov_size - 1; i ++){ // already + 1
            //std::string fake_func_name = "f_" + std::to_string(i+1); //TODO replace it with real function name?
            std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
            if (!tree.nodeExists(fake_func_name, i+2)) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i+1, 1, 1, -1, i+2);
              g_cov_call_stack.push_back(fake_func_name);
            } else {
              g_cov_call_stack.push_back(fake_func_name);
            }
          }
          
          tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
          for (auto it = result.begin(); it != result.end(); ++it) {
            tree.addChildToNode(name, it.value(), -1, g_manager_size, 1,  0, std::stoi(it.key()), g_manager_size);
          }
          is_saved = 0;
          if (show_switch_tree) std::cout << tree << "\n";
        }

      } else { // g_cov_size != 0
        if (g_cov_call_stack[g_cov_call_stack.size() - 1].rfind("f_", 0) == 0) { // check if the name is start with f_
          if (g_cov_size == g_manager_size) {
            //LOG_STAT("SWITCH: add nodes to fake parent node\n");
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
            for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
            }
            is_saved = 0;
            if (show_switch_tree) std::cout << tree << "\n";

          } else if (g_cov_size + 1 == g_manager_size) {
            //LOG_STAT ("SWITCH: g_cov_size + 1 == g_manager_size\n");

            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size -1, 1, 1, -1,  g_manager_size);
            g_cov_call_stack.push_back(name);
            for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
            }
            is_saved = 0;
            if (show_switch_tree) std::cout << tree << "\n";

          } else if (g_cov_size == g_manager_size + 1) {
            //LOG_STAT ("SWITCH: we should handle the call stack pop when meet fake node\n");
            g_cov_call_stack.pop_back();
            if (g_cov_size == 1) {
              tree.addChildToNode("root", name, -1, g_manager_size, 1, 1, -1, g_manager_size);
              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
              }
            } else {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
              }
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";

          } else {
            if (g_manager_size - g_cov_size >= 2) {
            //LOG_STAT ("SWITCH: Handle others for fake function (g_manager_size - g_cov_size >= 2 && g_cov_size !=0 )\n");
            std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
           
            if (!tree.nodeExists(fake_func_name, 1)) {
              g_cov_size ++;
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, g_cov_size-1, 1, 1, -1, g_cov_size);
              g_cov_call_stack.push_back(fake_func_name);
            } else {
              g_cov_call_stack.push_back(fake_func_name);
            }

              for (int i = g_cov_size; i < g_manager_size; i ++){ // already + 1
                std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
                if (!tree.nodeExists(fake_func_name, i)) {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i, 1, 1, -1, i+1);
                  g_cov_call_stack.push_back(fake_func_name);
                } else {
                  g_cov_call_stack.push_back(fake_func_name);
                }
              }

            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);

            for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
            }
            is_saved = 0;
            } else {
              //LOG_STAT ("SWITCH: Handle others for fake function (g_cov_size - g_manager_size >= 2 && g_cov_size !=0 )\n");
              for (int i = 0; g_cov_size != g_manager_size + 1; i ++){ // already + 1
                g_cov_call_stack.pop_back();
                g_cov_size--;
              }
              
              // then add nodes
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
              
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 1, 1, -1, g_manager_size+1);

              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size+1, 1, 0, std::stoi(it.key()), g_manager_size+1);
              }
              is_saved = 0;
            } // end of else g_manager_size - g_cov_size >= 2
            if (show_switch_tree) std::cout << tree << "\n";
            
          }

        } else { // handle normal function calls
          if (g_cov_size == g_manager_size) {
            //LOG_STAT ("SWITCH: insert nodes inside a function all\n");
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
            for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(name, it.value(), -1, g_manager_size,  1, 0, std::stoi(it.key()), g_manager_size);
            }
            is_saved = 0;
            if (show_switch_tree) std::cout << tree << "\n";
          }
          else if (g_cov_size + 1 == g_manager_size) {
            //LOG_STAT ("SWITCH: insert new function call\n");
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size-1, 1, 1, -1, g_manager_size);
            g_cov_call_stack.push_back(name);
            for (auto it = result.begin(); it != result.end(); ++it) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], it.value(), -1, g_manager_size,  1, 0, std::stoi(it.key()), g_manager_size);
            }
            is_saved = 0;
            if (show_switch_tree)  std::cout << tree << "\n";
          }
          else if (g_cov_size == g_manager_size + 1) {
            //LOG_STAT ("SWITCH: Handling pop function call\n");
            if (g_cov_size == 1) {
              g_cov_call_stack.pop_back();
              tree.addChildToNode("root", name, -1, 0, 1, 1, -1, g_manager_size);
              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
              }
              if (show_switch_tree) std::cout << tree << "\n";
            } else {
              g_cov_call_stack.pop_back();
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
              }
            }
            is_saved = 0;
            if (show_switch_tree)
             std::cout << tree << "\n";
          } else {
            if (g_manager_size - g_cov_size >= 2) {
              //LOG_STAT ("SWITCH: Handle others for normal function (g_manager_size - g_cov_size >= 2 && g_cov_size !=0 )\n");
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
              if (!tree.nodeExists(fake_func_name, 1)) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, g_cov_size, 1, 1, -1, g_cov_size+1);
                g_cov_call_stack.push_back(fake_func_name);
              } else {
                g_cov_call_stack.push_back(fake_func_name);
              }
              
              for (int i = g_cov_size + 1; i < g_manager_size ; i ++){ // already + 1
                std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
                if (!tree.nodeExists(fake_func_name, i)) {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i, 1, 1, -1, i+1);
                  g_cov_call_stack.push_back(fake_func_name);
                } else {
                  g_cov_call_stack.push_back(fake_func_name);
                }
              }
              
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 1, 1, -1, g_manager_size);
              for (auto it = result.begin(); it != result.end(); ++it) {
                tree.addChildToNode(name, it.value(), -1, g_manager_size, 1, 0, std::stoi(it.key()), g_manager_size);
              }
              is_saved = 0;
              if (show_switch_tree) std::cout << tree << "\n";
              } else {
                //LOG_STAT ("SWITCH: Handle others for normal function (g_cov_size - g_manager_size >= 2 && g_cov_size !=0 )\n");
                
                // first pop out
                for (int i = 0; g_cov_size != g_manager_size + 1; i ++){ // already + 1
                  g_cov_call_stack.pop_back();
                  g_cov_size--;
                }
                
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 1, 1, -1, g_manager_size+1);
                for (auto it = result.begin(); it != result.end(); ++it) {
                  tree.addChildToNode(name, it.value(), -1, g_manager_size+1, 1, 0, std::stoi(it.key()), g_manager_size+1);
                }
                is_saved = 0;
                if (show_switch_tree) std::cout << tree << "\n";
              } // end of else g_cov_size - g_manager_size >= 2

          }
          if (show_switch_tree) std::cout << tree << "\n";
        } // end of check fake node (else)
      } // end of check g_cov_size (else)

      int cnt_after_add = tree.countTreeNodes();
      assert(cnt_after_add != cnt_before_add && "SWITCH: Tree node is not added!!!\n");
    }
  } else {
    // Handle NON-SWITCH cases
    // for the first node
    auto currentNode = tree.nodeExists(name, g_manager_size);
    if (!currentNode) {
      int cnt_before_add = tree.countTreeNodes();
       //LOG_STAT("Handle NON-switch case: creat two child nodes?\n");
      if (g_cov_size == 0){
        if (g_manager_size == 0){
          //LOG_STAT("NON-SWITCH: Add the first level nodes\n");
          if (if_branch_type == 2) {
            tree.addChildToNode("root", name, -1, 0, 0, 0, 0, g_manager_size);
            tree.addChildToNode("root", name, -1, 0, 0, 0, 1, g_manager_size);
            if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
          } else {
            tree.addChildToNode("root", name, -1, 0, 0, 0, 0, g_manager_size);
          }
          is_saved = 0;
          if (show_non_switch_tree) std::cout << tree << "\n";

        }
        if (g_manager_size == 1){
          //LOG_STAT ("NON-SWITCH: Encounter a function all\n");
          tree.addChildToNode("root", name, -1, 0, 0, 1, -1, g_manager_size);
          g_cov_call_stack.push_back(name);
          if (if_branch_type == 2) {  
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size+1); // add node to last node
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size,  0, 0, 1, g_manager_size+1);
            if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
          } else {
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size+1);
          }
          is_saved = 0;
          if (show_non_switch_tree) std::cout << tree << "\n";
        }
        if (g_manager_size >= 2){
            //LOG_STAT ("NON-SWITCH: Handling Direct Function Calls\n");
            std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
            if (!tree.nodeExists(fake_func_name, 1)) {
              tree.addChildToNode("root", fake_func_name, -1, 0, 0, 1, -1, 1);
              g_cov_call_stack.push_back(fake_func_name);
            } else {
              g_cov_call_stack.push_back(fake_func_name);
            }

            for (int i = 0; i < g_manager_size - g_cov_size -1 ; i ++){ // already + 1
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
              if (!tree.nodeExists(fake_func_name, i+2)) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i+1, 0, 1, -1, i+2);
                g_cov_call_stack.push_back(fake_func_name);
              } else {
                  g_cov_call_stack.push_back(fake_func_name);
              }
            }
           
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size,  0, 0, 0, g_manager_size); // add node to last node
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
        }
      } else { // g_cov_size != 0
        if (g_cov_call_stack[g_cov_call_stack.size() - 1].rfind("f_", 0) == 0) { // check if the name is start with f_
          //LOG_STAT ("NON-swith cases with fake function in g_cov_size !!!\n");
          if (g_cov_size == g_manager_size) {
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          } else if (g_cov_size + 1 == g_manager_size) {
            //LOG_STAT ("Non-SWITCH: g_cov_size + 1 == g_manager_size\n");
            std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size -1, 0, 1, -1, g_manager_size);
            g_cov_call_stack.push_back(name);
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0,  0, 0, g_manager_size); // add node to last node
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";

          } else if (g_cov_size == g_manager_size + 1) {
            //LOG_STAT ("NON-SWITCH: we should handle the call stack pop when meet fake node\n");
            g_cov_call_stack.pop_back();
            if (g_cov_size == 1) {
              if (if_branch_type == 2) {
                tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 1, g_manager_size);
                if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
              } else {
                  tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              }
            } else {
                if (show_non_switch_tree) std::cout << tree << "\n";
                if (if_branch_type == 2) {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
                  if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
                } else {
                    tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                }
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          } else {
            if (g_manager_size - g_cov_size >= 2) {
              //LOG_STAT ("NON-SWITCH: Handle others for fake function (g_manager_size - g_cov_size >= 2 && g_cov_size !=0 )\n");
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
              if (!tree.nodeExists(fake_func_name, 1)) {
                g_cov_size++;
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, g_cov_size-1, 0, 1, -1, g_cov_size);
                g_cov_call_stack.push_back(fake_func_name);
              } else {
                  g_cov_call_stack.push_back(fake_func_name);
              }

              for (int i = g_cov_size; i < g_manager_size ; i ++){ // already + 1
                std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
                if (!tree.nodeExists(fake_func_name, i)) {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i, 0, 1, -1, i+1);
                  g_cov_call_stack.push_back(fake_func_name);
                } else {
                    g_cov_call_stack.push_back(fake_func_name);
                }
              }
              
              if (if_branch_type == 2) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
                if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
              } else {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              }
              is_saved = 0;
              if (show_non_switch_tree) std::cout << tree << "\n";

            } else { // forg_cov_size -  g_manager_size >= 2
              //LOG_STAT ("NON-SWITCH: Handle others for fake function (g_cov_size - g_manager_size >= 2 && g_cov_size !=0 )\n");
              // first pop out
              for (int i = 0; g_cov_size != g_manager_size + 1; i ++){ // already + 1
                g_cov_call_stack.pop_back();
                g_cov_size--;
              }
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
              
              if (if_branch_type == 2) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 0, 0, 0, g_manager_size+1);
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 0, 0, 1, g_manager_size+1);
                if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
              } else {
                  tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size +1, 0, 0, 0, g_manager_size+1);
              }
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          }
        } else { // normal function calls
          if (g_cov_size == g_manager_size) {
            //LOG_STAT ("NON-SWITCH: insert nodes inside a function all\n");
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            //g_cov_call_stack.push_back(name);
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          }
          else if (g_cov_size + 1 == g_manager_size) {
            //LOG_STAT ("NON-SWITCH: insert new function call\n");
            tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_cov_size, 0, 1, -1, g_manager_size);
            g_cov_call_stack.push_back(name);
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          }
          else if (g_cov_size == g_manager_size + 1) {
            //LOG_STAT ("NON-SWITCH: Handling pop function call\n");
            if (g_cov_size == 1) {
              g_cov_call_stack.pop_back();
              if (if_branch_type == 2) {
                tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 1, g_manager_size);
                if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
              } else {
                  tree.addChildToNode("root", name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              }
            } else {
              g_cov_call_stack.pop_back();
              if (if_branch_type == 2) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
                if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
              } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              }
            }
            is_saved = 0;
            if (show_non_switch_tree) std::cout << tree << "\n";
          } else {
           if (g_manager_size - g_cov_size >= 2) {
            //LOG_STAT ("NON-SWITCH: Handle others for normal function (g_manager_size - g_cov_size >= 2 && g_cov_size !=0 )\n");
            std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_);
            if (!tree.nodeExists(fake_func_name, 1)) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, g_cov_size, 0, 1, -1, g_cov_size + 1);
              g_cov_call_stack.push_back(fake_func_name);
            } else {
              g_cov_call_stack.push_back(fake_func_name);
            }
            
            for (int i = g_cov_size + 1; i < g_manager_size ; i ++){ // already + 1
              std::string fake_func_name = "f_" + std::to_string(g_call_stack_manager.call_stack_hash_ + i + 1);
               if (!tree.nodeExists(fake_func_name, i)) {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], fake_func_name, -1, i, 0, 1, -1, i+1);
                g_cov_call_stack.push_back(fake_func_name);
               } else {
                g_cov_call_stack.push_back(fake_func_name);
               }

            }
            
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 1, g_manager_size);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size, 0, 0, 0, g_manager_size);
            }
            is_saved = 0;
          } else {
            //LOG_STAT ("NON-SWITCH: Handle others for normal function (g_cov_size - g_mamager_size >= 2 && g_cov_size !=0 )\n");
            // first pop out
            for (int i = 0; g_cov_size != g_manager_size + 1; i ++){ // already + 1
              g_cov_call_stack.pop_back();
              g_cov_size--;
            }
            
            if (if_branch_type == 2) {
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 0, 0, 0, g_manager_size+1);
              tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 0, 0, 1, g_manager_size+1);
              if (con_taken) unvisisted = 1; // mark unvisted branch to else branch; by default the if is visisted concretely
            } else {
                tree.addChildToNode(g_cov_call_stack[g_cov_call_stack.size()-1], name, -1, g_manager_size+1, 0, 0, 0, g_manager_size+1);
            }
            is_saved = 0;
          }
          }

        }  // end of check fake node (else)
      } // end of check g_cov_size (else)
      int cnt_after_add = tree.countTreeNodes();
      assert(cnt_after_add != cnt_before_add && "NON-SWITCH: Tree node is not added!!!\n");
    }
  } // end of check switch

  if (is_interesting && use_cottontail_map) {
    negatePathESCT(e, taken, name, op_name, unvisisted);
  }

  if ((is_interesting && !use_cottontail_map)) {
    negatePath(e, taken, name, op_name, unvisisted);
  }

  // take normal path
  addConstraint(e, taken, is_interesting); // THX: what is the purpose of this?
}

void Solver::addAddr(ExprRef e, ADDRINT addr) {
  llvm::APInt v(e->bits(), addr);
  addAddr(e, v);
}

void Solver::addAddr(ExprRef e, llvm::APInt addr) {
  if (e->isConcrete())
    return;

  if (last_interested_) {
    reset();
    // TODO: add optimize in z3
    syncConstraints(e);
    if (check() != z3::sat)
      return;
    z3::expr &z3_expr = e->toZ3Expr();

    // TODO: add unbound case
    z3::expr min_expr = getMinValue(z3_expr);
    z3::expr max_expr = getMaxValue(z3_expr);
    solveOne(z3_expr == min_expr);
    solveOne(z3_expr == max_expr);
  }

  addValue(e, addr);
}

void Solver::addValue(ExprRef e, ADDRINT val) {
  llvm::APInt v(e->bits(), val);
  addValue(e, v);
}

void Solver::addValue(ExprRef e, llvm::APInt val) {
  if (e->isConcrete())
    return;

#ifdef CONFIG_TRACE
  trace_addValue(e, val);
#endif

  ExprRef expr_val = g_expr_builder->createConstant(val, e->bits());
  ExprRef expr_concrete = g_expr_builder->createBinaryExpr(Equal, e, expr_val);

  addConstraint(expr_concrete, true, false);
}

void Solver::solveAll(ExprRef e, llvm::APInt val) {
  if (last_interested_) {
    std::string postfix = "";
    ExprRef expr_val = g_expr_builder->createConstant(val, e->bits());
    ExprRef expr_concrete = g_expr_builder->createBinaryExpr(Equal, e, expr_val);

    reset();
    syncConstraints(e);
    addToSolver(expr_concrete, false);

    if (check() != z3::sat) {
      // Optimistic solving
      reset();
      addToSolver(expr_concrete, false);
      postfix = "optimistic";
    }

    z3::expr z3_expr = e->toZ3Expr();
    while(true) {
      if (!checkAndSave(postfix))
        break;
      z3::expr value = getPossibleValue(z3_expr);
      add(value != z3_expr);
    }
  }
  addValue(e, val);
}

UINT8 Solver::getInput(ADDRINT index) {
  assert(index < inputs_.size());
  return inputs_[index];
}

void Solver::checkOutDir() {
  // skip if there is no out_dir
  if (out_dir_.empty()) {
    //LOG_INFO("Since output directory is not set, use stdout\n");
    return;
  }

  struct stat info;
  if (stat(out_dir_.c_str(), &info) != 0
      || !(info.st_mode & S_IFDIR)) {
    //LOG_FATAL("No such directory\n");
    exit(-1);
  }
}

void Solver::readInput() {
  std::ifstream ifs (input_file_, std::ifstream::in | std::ifstream::binary);
  if (ifs.fail()) {
    //LOG_FATAL("Cannot open an input file\n");
    exit(-1);
  }

  char ch;
  while (ifs.get(ch))
    inputs_.push_back((UINT8)ch);
}

std::vector<UINT8> Solver::getConcreteValues() {
  // TODO: change from real input
  z3::model m = solver_.get_model();
  unsigned num_constants = m.num_consts();
  std::vector<UINT8> values = inputs_;

  for (unsigned i = 0; i < num_constants; i++) {
    z3::func_decl decl = m.get_const_decl(i);
    z3::expr e = m.get_const_interp(decl);
    z3::symbol name = decl.name();

    if (name.kind() == Z3_INT_SYMBOL) {
      int value = e.get_numeral_int();
      values[name.to_int()] = (UINT8)value;
    }
  }
  
  return values;
}

void Solver::saveValues(const std::string& postfix) {
  std::vector<UINT8> values = getConcreteValues();

  // If no output directory is specified, then just print it out
  if (out_dir_.empty()) {
    printValues(values);
    return;
  }

  std::string fname = out_dir_+ "/" + toString6digit(num_generated_);
  // Add postfix to record where it is genereated
  if (!postfix.empty())
      fname = fname + "-" + postfix;
  ofstream of(fname, std::ofstream::out | std::ofstream::binary);
  LOG_INFO("New testcase: " + fname + "\n"); // THX

  if (of.fail())
    //LOG_FATAL("Unable to open a file to write results\n");
    // TODO: batch write
    for (unsigned i = 0; i < values.size(); i++) {
      char val = values[i];
      of.write(&val, sizeof(val));
    }

  of.close();
  num_generated_++;
}

void Solver::printValues(const std::vector<UINT8>& values) {
  fprintf(stderr, "[INFO] Values: ");
  for (unsigned i = 0; i < values.size(); i++) {
    fprintf(stderr, "\\x%02X", values[i]);
  }
  fprintf(stderr, "\n");
}

z3::expr Solver::getPossibleValue(z3::expr& z3_expr) {
  z3::model m = solver_.get_model();
  return m.eval(z3_expr);
}

z3::expr Solver::getMinValue(z3::expr& z3_expr) {
  push();
  z3::expr value(context_);
  while (true) {
    if (checkAndSave()) {
      value = getPossibleValue(z3_expr);
      solver_.add(z3::ult(z3_expr, value));
    }
    else
      break;
  }
  pop();
  return value;
}

z3::expr Solver::getMaxValue(z3::expr& z3_expr) {
  push();
  z3::expr value(context_);
  while (true) {
    if (checkAndSave()) {
      value = getPossibleValue(z3_expr);
      solver_.add(z3::ugt(z3_expr, value));
    }
    else
      break;
  }
  pop();
  return value;
}

void Solver::addToSolver(ExprRef e, bool taken) {
  e->simplify();
  if (!taken) {
    e = g_expr_builder->createLNot(e);
  }
  add(e->toZ3Expr());
}

void Solver::syncConstraints(ExprRef e) {
  std::set<std::shared_ptr<DependencyTree<Expr>>> forest;
  DependencySet* deps = e->getDependencies();

  for (const size_t& index : *deps)
    forest.insert(dep_forest_.find(index));

  for (std::shared_ptr<DependencyTree<Expr>> tree : forest) {
    std::vector<std::shared_ptr<Expr>> nodes = tree->getNodes();
    for (std::shared_ptr<Expr> node : nodes) {
      if (isRelational(node.get()))
        addToSolver(node, true);
      else {
        // Process range-based constraints
        bool valid = false;
        for (INT32 i = 0; i < 2; i++) {
          ExprRef expr_range = getRangeConstraint(node, i);
          if (expr_range != NULL) {
            addToSolver(expr_range, true);
            valid = true;
          }
        }

        // One of range expressions should be non-NULL
        if (!valid)
          LOG_INFO(std::string(__func__) + ": Incorrect constraints are inserted\n");
      }
    }
  }

  checkFeasible();
}

void Solver::addConstraint(ExprRef e, bool taken, bool is_interesting) {
  if (auto NE = castAs<LNotExpr>(e)) {
    addConstraint(NE->expr(), !taken, is_interesting);
    return;
  }
  if (!addRangeConstraint(e, taken)) {
    addNormalConstraint(e, taken);
  }
}

void Solver::addConstraint(ExprRef e) {
  // If e is true, then just skip
  if (e->kind() == Bool) {
    QSYM_ASSERT(castAs<BoolExpr>(e)->value());
    return;
  }
  if (e->isConcrete())
    return;
  dep_forest_.addNode(e);
}

bool Solver::addRangeConstraint(ExprRef e, bool taken) {
  if (!isConstSym(e))
    return false;

  Kind kind = Invalid;
  ExprRef expr_sym, expr_const;
  parseConstSym(e, kind, expr_sym, expr_const);
  ExprRef canonical = NULL;
  llvm::APInt adjustment;
  getCanonicalExpr(expr_sym, &canonical, &adjustment);
  llvm::APInt value = static_pointer_cast<ConstantExpr>(expr_const)->value();

  if (!taken)
    kind = negateKind(kind);

  canonical->addConstraint(kind, value,
      adjustment);
  addConstraint(canonical);
  return true;
}

void Solver::addNormalConstraint(ExprRef e, bool taken) {
  if (!taken)
    e = g_expr_builder->createLNot(e);
  addConstraint(e);
}

ExprRef Solver::getRangeConstraint(ExprRef e, bool is_unsigned) {
  Kind lower_kind = is_unsigned ? Uge : Sge;
  Kind upper_kind = is_unsigned ? Ule : Sle;
  RangeSet *rs = e->getRangeSet(is_unsigned);
  if (rs == NULL)
    return NULL;

  ExprRef expr = NULL;
  for (auto i = rs->begin(), end = rs->end();
      i != end; i++) {
    const llvm::APSInt& from = i->From();
    const llvm::APSInt& to = i->To();
    ExprRef bound = NULL;

    if (from == to) {
      // can simplify this case
      ExprRef imm = g_expr_builder->createConstant(from, e->bits());
      bound = g_expr_builder->createEqual(e, imm);
    }
    else
    {
      ExprRef lb_imm = g_expr_builder->createConstant(i->From(), e->bits());
      ExprRef ub_imm = g_expr_builder->createConstant(i->To(), e->bits());
      ExprRef lb = g_expr_builder->createBinaryExpr(lower_kind, e, lb_imm);
      ExprRef ub = g_expr_builder->createBinaryExpr(upper_kind, e, ub_imm);
      bound = g_expr_builder->createLAnd(lb, ub);
    }
    if (expr == NULL)
      expr = bound;
    else
      expr = g_expr_builder->createLOr(expr, bound);
  }

  return expr;
}


bool Solver::isInterestingJcc(ExprRef rel_expr, bool taken, ADDRINT pc) {
  bool interesting = trace_.isInterestingBranch(pc, taken);
  // record for other decision
  last_interested_ = interesting;
  return interesting;
}

/**
 * @brief Stores a (key, value) pair in a JSON file, where key is std::string
 *        and value is a Z3 expression (converted to a string).
 *
 * The function reads (if exists) and updates a JSON file named "constraints.json".
 *
 * @param key        The JSON key as an std::string.
 * @param constraint The Z3 expression to be stored (converted to a string).
 */

void storeUniqueConstraintExprInJson(const std::string& key, const z3::expr& constraint)
{
    // 1. Read existing JSON from file (if present).
    std::ifstream ifs("path-constraints-expr.json");
    json j;
    if (ifs.good()) {
        try {
            ifs >> j;  // Attempt to parse existing file into j
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse path-constraints-expr.json: " << e.what() << std::endl;
            // If parsing fails, we just use an empty JSON object.
        }
    }
    ifs.close();

    // 2. Convert the z3::expr to a string and store it under the given key.
    //    Example: j["myKey"] = "(and (> x 0) (< x 100))"
    j[key] = constraint.to_string();

    // 3. Write the updated JSON back to the file.
    std::ofstream ofs("path-constraints-expr.json");
    if (!ofs.is_open()) {
      std::cerr << "Error: Could not open path-constraints-expr.json for writing.\n";
      return;
    }
    ofs << j.dump(4) << std::endl;
    ofs.close();
}


/**
 * @brief Stores a (key, value) pair in a JSON file, where key is std::string
 *        and value is a Z3 expression (converted to a string).
 *
 * Each duplicate key is stored with a unique suffix (e.g., branch_1-d1, branch_1-d2).
 *
 * @param key        The JSON key as an std::string.
 * @param constraint The Z3 expression to be stored (converted to a string).
 */
void storeConstraintExprInJson(const std::string& key, const z3::expr& constraint)
{
    using json = nlohmann::json;

    // Open the file for reading the existing JSON.
    std::ifstream ifs("path-constraints-expr.json");
    json existing_json = json::object(); // Initialize as an empty object.

    if (ifs.good()) {
        try {
            ifs >> existing_json; // Read the existing JSON content.
        } catch (const std::exception& e) {
            //std::cerr << "Warning: Could not parse path-constraints-expr.json: " << e.what() << std::endl;
        }
    }
    ifs.close();

    // Determine the unique key by adding a suffix if duplicates exist.
    std::string unique_key = key;
    int duplicate_count = 1;

    while (existing_json.contains(unique_key)) {
        unique_key = key + "-d" + std::to_string(duplicate_count);
        duplicate_count++;
    }

    // Store the constraint under the unique key.
    existing_json[unique_key] = constraint.to_string();

    // Write the updated JSON back to the file.
    std::ofstream ofs("path-constraints-expr.json");
    if (!ofs.is_open()) {
        //std::cerr << "Error: Could not open path-constraints-expr.json for writing.\n";
        return;
    }

    ofs << existing_json.dump(4) << std::endl; // Pretty print with 4 spaces indentation.
    ofs.close();
}

/**
 * @brief Stores a (key, value) pair in a JSON file, where key is std::string
 *        and value is the SMT-LIB representation of constraints as a string.
 *
 * The logic:
 * 1. If the name (key) does not exist, insert it.
 * 2. If the name exists but the constraint string is different (excluding differences in [k!n] indices),
 *    treat it as redundant and do not insert.
 * 3. If the name exists and the constraint string is different (beyond [k!n] differences),
 *    insert it with a `-d` suffix.
 *
 * @param key        The JSON key as an std::string.
 * @param constraint The Z3 expression to be stored (converted to a string).
 */
void storeConstraintExprInJsonReduced(const std::string& key, const z3::expr& constraint)
{
    json j;

    // Open the file for reading the existing JSON.
    std::ifstream ifs("path-constraints-expr.json");
    if (ifs.good()) {
        try {
            ifs >> j; // Read the existing JSON content.
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse path-constraints-expr.json: " << e.what() << std::endl;
        }
    }
    ifs.close();

    std::string smt2 = constraint.to_string();

    // Function to check for redundancy based on [k!n] indices
    auto isRedundantConstraint = [](const std::string& existing, const std::string& current) -> bool {
        auto normalize = [](const std::string& input) -> std::string {
            std::string result;
            size_t i = 0;
            while (i < input.size()) {
                if (input[i] == 'k' && i + 2 < input.size() && input[i + 1] == '!' && std::isdigit(input[i + 2])) {
                    result += "k!X"; // Normalize k!n to k!X
                    i += 2;
                    while (i < input.size() && std::isdigit(input[i])) {
                        ++i;
                    }
                } else {
                    result += input[i];
                    ++i;
                }
            }
            return result;
        };

        return normalize(existing) == normalize(current);
    };

    // Check for the key
    if (j.contains(key)) {
        std::string existing_constraint = j[key].get<std::string>();

        // If redundant, do not insert
        if (isRedundantConstraint(existing_constraint, smt2)) {
            return;
        }

        // If not redundant but different, append a `-d` suffix to the key
        int duplicate_count = 1;
        std::string new_key = key;
        while (j.contains(new_key)) {
            new_key = key + "-d" + std::to_string(duplicate_count);
            ++duplicate_count;
        }
        j[new_key] = smt2;
    } else {
        // Insert if the key does not exist
        j[key] = smt2;
    }

    // Write the updated JSON back to the file
    std::ofstream ofs("path-constraints-expr.json");
    if (!ofs.is_open()) {
        std::cerr << "Error: Could not open path-constraints-expr.json for writing.\n";
        return;
    }
    ofs << j.dump(4) << std::endl; // Pretty print with 4 spaces indentation.
    ofs.close();
}

/**
 * @brief Checks whether a constraint should be stored in the JSON file based on redundancy rules.
 *
 * The logic:
 * 1. If the name does not exist, allow insertion.
 * 2. If the name exists but the constraint string is redundant (only differing in [k!n] indices), reject.
 * 3. If the name exists and the constraint string is different (beyond [k!n] differences), allow insertion with a `-d` suffix.
 *
 * @param name       The JSON key as an std::string.
 * @param constraint The Z3 expression to be evaluated (converted to a string).
 * @param file_path  The JSON file path.
 * @return           True if the record should be stored, false otherwise.
 */
bool shouldStoreConstraint(const std::string& name, const z3::expr& constraint, const std::string& file_path) {
    json j;

    // Open the file for reading the existing JSON.
    std::ifstream ifs(file_path);
    if (ifs.good()) {
        try {
            ifs >> j; // Read the existing JSON content.
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse " << file_path << ": " << e.what() << std::endl;
        }
    }
    ifs.close();

    std::string smt2 = constraint.to_string();

    // Function to check for redundancy based on [k!n] indices
    auto isRedundantConstraint = [](const std::string& existing, const std::string& current) -> bool {
        auto normalize = [](const std::string& input) -> std::string {
            std::string result;
            size_t i = 0;
            while (i < input.size()) {
                if (input[i] == 'k' && i + 2 < input.size() && input[i + 1] == '!' && std::isdigit(input[i + 2])) {
                    result += "k!X"; // Normalize k!n to k!X
                    i += 2;
                    while (i < input.size() && std::isdigit(input[i])) {
                        ++i;
                    }
                } else {
                    result += input[i];
                    ++i;
                }
            }
            return result;
        };

        return normalize(existing) == normalize(current);
    };

    // Check for the name
    if (j.contains(name)) {
        std::string existing_constraint = j[name].get<std::string>();

        // If redundant, do not allow storage
        if (isRedundantConstraint(existing_constraint, smt2)) {
            return false;
        }

        // If not redundant but different, allow storage with a `-d` suffix
        int duplicate_count = 1;
        std::string new_key = name;
        while (j.contains(new_key)) {
            new_key = name + "-d" + std::to_string(duplicate_count);
            ++duplicate_count;
        }
        j[new_key] = smt2;
    } else {
        // Allow storage if the name does not exist
        j[name] = smt2;
    }

    // Write the updated JSON back to the file
    std::ofstream ofs(file_path);
    if (!ofs.is_open()) {
        std::cerr << "Error: Could not open " << file_path << " for writing.\n";
        return false;
    }
    ofs << j.dump(4) << std::endl; // Pretty print with 4 spaces indentation.
    ofs.close();

    return true;
}

void storeInputBytesInJson(const std::vector<uint8_t>& inputs, const std::string& filePath = "input-bytes.json") {
    using json = nlohmann::json;

    // 1. Read existing JSON from the file (if present)
    std::ifstream ifs(filePath);
    json j;
    if (ifs.good()) {
        try {
            ifs >> j; // Attempt to parse existing file into JSON object
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse " << filePath << ": " << e.what() << std::endl;
            // If parsing fails, start with an empty JSON object
            j = json::object();
        }
    }
    ifs.close();

    // 2. Check if the file already contains data; if so, do not store anything
    if (!j.empty()) {
        std::cerr << "File " << filePath << " already exists and contains data. No data stored.\n";
        return;
    }

    // 3. Use a map to enforce numeric ordering of keys
    std::map<int, std::string> ordered_data;
    for (size_t i = 0; i < inputs.size(); ++i) {
        uint8_t byte = inputs[i];

        // Convert byte to a string: escape non-ASCII or control characters
        if (byte >= 32 && byte <= 126) {
            // Printable ASCII range
            ordered_data[static_cast<int>(i)] = std::string(1, static_cast<char>(byte));
        } else {
            // Encode non-printable or invalid UTF-8 bytes as a hexadecimal escape sequence
            char hex_representation[5];
            snprintf(hex_representation, sizeof(hex_representation), "\\x%02X", byte);
            ordered_data[static_cast<int>(i)] = hex_representation;
        }
    }

    // Convert the ordered map into JSON
    for (const auto& [key, value] : ordered_data) {
        j[std::to_string(key)] = value; // Store keys as strings in JSON
    }

    // 4. Write the sorted JSON object to the file
    std::ofstream ofs(filePath);
    if (!ofs.is_open()) {
        std::cerr << "Error: Could not open " << filePath << " for writing.\n";
        return;
    }
    ofs << j.dump(4) << std::endl; // Pretty print JSON with 4 spaces indentation
    ofs.close();

}

/**
 * @brief Stores a (key, value) pair in a JSON file, where key is std::string
 *        and value is the output of solver.to_smt2().
 *
 * The function reads (if exists) and updates a JSON file named "path-constraints.json".
 *
 * @param key        The JSON key as an std::string.
 * @param smt2       The SMT-LIB representation of constraints as a string.
 */
void storeConstraintInJson(const std::string& key, const std::string& smt2)
{
    json j;

    // 1. Read existing JSON from file (if present).
    std::ifstream ifs("path-constraints.json");
    if (ifs.good()) {
        try {
            ifs >> j;
        } catch (const std::exception& e) {
            std::cerr << "Warning: Could not parse path-constraints.json: " << e.what() << std::endl;
        }
    }
    ifs.close();

    // 2. Simplify the SMT-LIB constraints
    std::string simplified_smt2 = smt2;

    // Remove redundant metadata (e.g., set-info)
    size_t metadata_pos = simplified_smt2.find("(set-info");
    if (metadata_pos != std::string::npos) {
        size_t end_metadata_pos = simplified_smt2.find(")", metadata_pos);
        if (end_metadata_pos != std::string::npos) {
            simplified_smt2.erase(metadata_pos, end_metadata_pos - metadata_pos + 1);
        }
    }

    // Remove redundant let expressions (manual inlining example)
    size_t let_pos = simplified_smt2.find("(let ");
    while (let_pos != std::string::npos) {
        size_t end_let_pos = simplified_smt2.find(")", let_pos);
        if (end_let_pos != std::string::npos) {
            simplified_smt2.erase(let_pos, end_let_pos - let_pos + 1);
        }
        let_pos = simplified_smt2.find("(let ");
    }

    // Flatten redundant conjunctions/disjunctions (manual simplification)
    size_t and_pos = simplified_smt2.find("(and ");
    while (and_pos != std::string::npos) {
        size_t end_and_pos = simplified_smt2.find(")", and_pos);
        if (end_and_pos != std::string::npos) {
            simplified_smt2.replace(and_pos, 5, "");
            simplified_smt2.erase(end_and_pos - 4, 1);
        }
        and_pos = simplified_smt2.find("(and ");
    }

    // 3. Store the simplified SMT-LIB constraints in JSON
    j[key] = simplified_smt2;

    // 4. Write the updated JSON back to the file.
    std::ofstream ofs("path-constraints.json");
    if (!ofs.is_open()) {
        std::cerr << "Error: Could not open path-constraints.json for writing.\n";
        return;
    }
    ofs << j.dump(4) << std::endl;
    ofs.close();
}



double getEnvDouble(const char* varName) {
    const char* value = std::getenv(varName);
    if (value == nullptr) {
        // Environment variable not set; return a default
        return 0.0;
    }

    try {
        // Convert the string to a double
        // Debug: Print the raw environment variable value
        //std::cout << "Environment variable " << varName << " = " << value << std::endl;
        return std::stod(value);
    } catch (const std::invalid_argument&) {
        // If the string is not a valid floating-point representation
        //std::cout << "return wrong!!!!!! for " << varName << "\n";
        return 0.0;
    } catch (const std::out_of_range&) {
        // If the number is out of range for a double
        //std::cout << "return wrong!!!!!! for " << varName << "\n";
        return 0.0;
    }
}

void Solver::negatePath(ExprRef e, bool taken, char* name, char* op_name, bool unvisited) {
  total_solving ++;
  reset();
  syncConstraints(e);
  addToSolver(e, !taken);
  std::vector<UINT8> values = inputs_;
  storeInputBytesInJson (values);
  bool sat = checkAndSave();
  int call_stack_size = g_call_stack_manager.call_stack_.size();
  if (!sat) {
    reset();
    // optimistic solving
    addToSolver(e, !taken);
    checkAndSave("optimistic");
    
    if (strcmp(op_name, "switch") == 0){
      //LOG_STAT("OPT solving, in switch-cases ... \n");
      std::optional<long unsigned int> value = extractConstantValueAsUInt(e.get()->toZ3Expr());
     
      std::string file_name = extractBeforeFirstNumber(name);
      const std::string filePath = std::string("./") + file_name + std::string(".json");
      json result = getValuesByKey(filePath, name);
      std::string case_name = findValueByKey(result, *value);;
      
      auto* node_branch = tree.findNodeByNameAndBranchID(case_name, 1,  *value,  call_stack_size);
      if (node_branch == nullptr) return; // TODO fix it
      assert(node_branch && "Node (in switch) found from tree is NULL!!!\n");
      if (node_branch->taken == 1) invalid_solving ++;

      std::string key = case_name + "_cs_" + std::to_string(call_stack_size) +"_bi_" + std::to_string(*value);
      
      storeConstraintExprInJson(key, e.get()->toZ3Expr());
      node_branch->taken = 1;
     } else {
      //LOG_STAT("OPT solving, in NON-switch-cases ... \n");
      auto* node_function = tree.findNodeByNameAndBranchID(name, 0, -1, call_stack_size); // try to find the function node first
      auto* node_branch = tree.findNodeByNameAndBranchID(name, 0,  unvisited, call_stack_size);
      if (node_branch) {
        if (node_branch->taken == 1) invalid_solving ++;
        std::string key = std::string(name) + "_cs_" + std::to_string(call_stack_size) + "_bi_" + std::to_string(unvisited);
        storeConstraintExprInJson(key, e.get()->toZ3Expr());
        node_branch->taken = 1;
      }
      if (node_function) {
        node_function->taken = 1;
      }
      if (!node_function && !node_branch) {
        assert("No nodes found!!!\n");
      }
     }
  }  else { // sat only mark nodes
    //up date tree node
    //LOG_STAT("Normal solving, mark the node value ... \n");
    if (strcmp(op_name, "switch") == 0){
      //LOG_STAT("Normal solving, in switch-cases ... \n");
      std::optional<long unsigned int> value = extractConstantValueAsUInt(e.get()->toZ3Expr());
      std::string file_name = extractBeforeFirstNumber(name);
      const std::string filePath = std::string("./") + file_name + std::string(".json");

      json result = getValuesByKey(filePath, name);
      std::string case_name = findValueByKey(result, *value);;

      auto* node_branch = tree.findNodeByNameAndBranchID(case_name, 1, *value, call_stack_size);
      if (node_branch == nullptr) return; // TODO fix it
      assert(node_branch && "Node (in switch) found from tree is NULL!!!\n");
      if (node_branch->taken == 1) invalid_solving ++;
        std::string key = std::string(name) + "_cs_" + std::to_string(call_stack_size) + "_bi_" + std::to_string(unvisited);
        storeConstraintExprInJson(key, e.get()->toZ3Expr());
        node_branch->taken = 1;

    } else {
      //LOG_STAT("Normal solving, in NON-switch-cases ... \n");
      auto* node_function = tree.findNodeByNameAndBranchID(name, 0, -1, call_stack_size); // try to find the function node first
      auto* node_branch = tree.findNodeByNameAndBranchID(name, 0, unvisited, call_stack_size);
      if (node_branch) {
        if (node_branch->taken == 1) invalid_solving ++;
        std::string key = std::string(name) + "_cs_" + std::to_string(call_stack_size) + "_bi_" + std::to_string(unvisited);
        storeConstraintExprInJson(key, e.get()->toZ3Expr());
        node_branch->taken = 1;
      }
      if (node_function) {
        node_function->taken = 1;
      }
      if (!node_function && !node_branch) {
        assert("No nodes found!!!\n");
      }
    }
  }
  // save the results again in case there is not ret instruction before exit the program
  if (is_saved == 0)
        tree.saveToJsonFile("global-tree.json");
}

void Solver::negatePathESCT(ExprRef e, bool taken, char* name, char* op_name, bool unvisited) {
  //std::cout << "THX in negatePath with constraints (in negatePathESCT): " << e.get()->toZ3Expr() << "\n";
  //std::cout << "Calling negatePathESCT\n";
  // The logic would be
  // 1. find the node in the tree
  //   (1) if it's taken, don't invoke solver
  //   (2) if it's not taken, use solver then
  //
  std::vector<UINT8> values = inputs_;
  storeInputBytesInJson (values);

  bool use_gpt_solving = getEnvBool("USE_GPT_SOLVING");
  bool use_result_validator = getEnvBool("USE_RESIULT_VALIDATOR");

  const double alpha = getEnvDouble("ALPHA");              // Priority for untaken branches
  const double beta = getEnvDouble("BETA");               // Priority for rarely visited nodes
  const double gamma = getEnvDouble("GAMMA");              // Reward for depth
  const double threshold = getEnvDouble("THRESHOLD");

  int expr_size = e.get()->toZ3Expr().num_args();
  if (expr_size >10) return;

  int call_stack_size = g_call_stack_manager.call_stack_.size();
  
  if (strcmp(op_name, "switch") == 0){
      //LOG_STAT("OPT solving, in switch-cases ... \n");
      std::optional<long unsigned int> value = extractConstantValueAsUInt(e.get()->toZ3Expr());
      std::string file_name = extractBeforeFirstNumber(name);
      const std::string filePath = std::string("./") + file_name + std::string(".json");
      json result = getValuesByKey(filePath, name);
      std::string case_name = findValueByKey(result, *value);

      auto* node_branch = tree.findNodeByNameAndBranchID(case_name, 1,  *value,  call_stack_size);

      if (!node_branch) {
        return;
      }

      assert(node_branch && "Node (in switch) found from tree is NULL!!!\n");
      std::string key = case_name + "_cs_" + std::to_string(call_stack_size) +"_bi_" + std::to_string(*value);
      bool should_store = shouldStoreConstraint (key, e.get()->toZ3Expr(), "path-constraints-expr.json");
      //if (node_branch->taken != 1 || node_branch->visit_cnt < 2) {
      if (!areAllNodesTakenAndVisited<std::string>(node_branch, alpha, beta, gamma, threshold) && node_branch->branch_id != -1
        /*&& should_store*/) {
        if (!use_gpt_solving) {
          //LOG_STAT("Using Z3 solving ... \n");
          reset();
          syncConstraints(e);
          addToSolver(e, !taken);
          bool sat = checkAndSave();
          if (!sat) {
            reset();
            // optimistic solving
            addToSolver(e, !taken);
            bool sat_opt = checkAndSave("optimistic");
            if (!sat_opt){
              // even opt can not solve it, we may store them for further analysis
              //LOG_STAT("UNSAT\n");
            }

          }
          node_branch->taken = 1;
          node_branch->visit_cnt ++;
        } else {
            //LOG_STAT("Using GPT solving ... \n");
            reset();
            syncConstraints(e);
            addToSolver(e, !taken);
        }
      } else {
          ;
      }

     } else {
      //LOG_STAT("OPT solving, in NON-switch-cases ... \n");
      auto* node_function = tree.findNodeByNameAndBranchID(name, 0, -1, call_stack_size); // try to find the function node first

      auto* node_branch = tree.findNodeByNameAndBranchID(name, 0,  unvisited, call_stack_size);
      if (!node_function && !node_branch) {
        assert("No nodes found!!!\n");
      }

      if (!node_function && !node_branch) {
        //TODO: some corner cases?
        return;
      }

      std::string key = std::string(name) + "_cs_" + std::to_string(call_stack_size) + "_bi_" + std::to_string(unvisited);
      bool should_store = shouldStoreConstraint (key, e.get()->toZ3Expr(), "path-constraints-expr.json");
      if (!areAllNodesTakenAndVisited<std::string>(node_branch, alpha, beta, gamma, threshold) && node_branch->branch_id != -1
          /*&& should_store*/) {
         if (!use_gpt_solving) {
          //LOG_STAT("Using Z3 solving ... \n");
          reset();
          syncConstraints(e);
          addToSolver(e, !taken);
          bool sat = checkAndSave();
          if (!sat) {
            reset();
            // optimistic solving
            addToSolver(e, !taken);
            bool sat_opt = checkAndSave("optimistic");
            if (!sat_opt){
              //LOG_STAT("UNSAT\n");
            }
          }

          node_branch->taken = 1;
          node_branch->visit_cnt ++;

        } else {
          //LOG_STAT("Using GPT solving ... \n");
          reset();
          syncConstraints(e);
          addToSolver(e, !taken);
        }
      } else {
        ;
    }

  }
  // save the results again in case there is not ret instruction before exit the program
  if (is_saved == 0)
    tree.saveToJsonFile("global-tree.json");
}

void Solver::solveOne(z3::expr z3_expr) {
  push();
  add(z3_expr);
  checkAndSave();
  pop();
}

void Solver::checkFeasible() {
#ifdef CONFIG_TRACE
  if (check() == z3::unsat)
    LOG_FATAL("Infeasible constraints: " + solver_.to_smt2() + "\n");
#endif
}

} // namespace qsym
