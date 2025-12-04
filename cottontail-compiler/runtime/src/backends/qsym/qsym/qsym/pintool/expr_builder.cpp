#include "expr_builder.h"
#include "solver.h"
#include "call_stack_manager.h"
#include <llvm/ADT/StringRef.h>

namespace qsym {

namespace {
const INT32 kComplexityThresholdForSimplify = 16;

void addUses(ExprRef e) {
  for (INT i = 0; i < e->num_children(); i++)
    e->getChild(i)->addUse(e);
}

// utility function for checking values
bool isZero(ExprRef e) {
  ConstantExprRef ce = castAs<ConstantExpr>(e);
  return ce != NULL && ce->isZero();
}

bool isOne(ExprRef e) {
  ConstantExprRef ce = castAs<ConstantExpr>(e);
  return ce != NULL && ce->isOne();
}

bool isAllOnes(ExprRef e) {
  ConstantExprRef ce = castAs<ConstantExpr>(e);
  return ce != NULL && ce->isAllOnes();
}

} // namespace

bool canEvaluateTruncated(ExprRef e, UINT bits, UINT depth=0) {
  if (depth > 1)
    return false;

  switch (e->kind()) {
    default:
      return false;
    case Mul:
      return canEvaluateTruncated(e->getChild(0), depth + 1)
        && canEvaluateTruncated(e->getChild(1), depth + 1);
    case UDiv:
    case URem: {
      UINT high_bits = e->bits() - bits;
      if (e->getChild(0)->countLeadingZeros() >= high_bits
          && e->getChild(1)->countLeadingZeros() >= high_bits) {
        return canEvaluateTruncated(e->getChild(0), depth + 1)
          && canEvaluateTruncated(e->getChild(1), depth + 1);
      }
      else
        return false;
    }
    case ZExt:
    case SExt:
    case Constant:
    case Concat:
      return true;
  }
}

ExprRef evaluateInDifferentType(ExprBuilder* builder, ExprRef op, UINT32 index, UINT32 bits) {
  // TODO: recursive evaluation
  switch (op->kind()) {
    default:
      return NULL;
    case Mul:
    case UDiv:
    case URem: {
      ExprRef e1 = builder->createExtract(op->getChild(0), index, bits);
      ExprRef e2 = builder->createExtract(op->getChild(1), index, bits);

      return builder->createBinaryExpr(op->kind(),
          builder->createExtract(op->getChild(0), index, bits),
          builder->createExtract(op->getChild(1), index, bits));
    }
  }
}

ExprBuilder::ExprBuilder() : next_(NULL) {}

void ExprBuilder::setNext(ExprBuilder* next) {
  next_ = next;
}

ExprBuilder* SymbolicExprBuilder::create() {
  ExprBuilder* base = new BaseExprBuilder();
  ExprBuilder* commu = new CommutativeExprBuilder();
  ExprBuilder* common = new CommonSimplifyExprBuilder();
  ExprBuilder* const_folding = new ConstantFoldingExprBuilder();
  ExprBuilder* symbolic = new SymbolicExprBuilder();
  ExprBuilder* cache = new CacheExprBuilder();

  // commu -> symbolic -> common -> constant folding -> base
  commu->setNext(symbolic);
  symbolic->setNext(common);
  common->setNext(const_folding);
  const_folding->setNext(cache);
  cache->setNext(base);
  return commu;
}

ExprBuilder* ConstantFoldingExprBuilder::create() {
  // constant folding -> base
  ExprBuilder* const_folding = new ConstantFoldingExprBuilder();
  ExprBuilder* base = new BaseExprBuilder();

  // commu -> symbolic -> common -> constant folding -> base
  const_folding->setNext(base);
  return const_folding;
}

ExprRef ExprBuilder::createTrue() {
  return createBool(true);
}

ExprRef ExprBuilder::createFalse() {
  return createBool(false);
}

ExprRef ExprBuilder::createMsb(ExprRef e) {
  return createExtract(e, e->bits() - 1, 1);
}

ExprRef ExprBuilder::createLsb(ExprRef e) {
  return createExtract(e, 0, 1);
}

ExprRef ExprBuilder::bitToBool(ExprRef e) {
  QSYM_ASSERT(e->bits() == 1);
  ExprRef one = createConstant(1, e->bits());
  return createEqual(e, one);
}

ExprRef ExprBuilder::boolToBit(ExprRef e, UINT32 bits) {
  ExprRef e1 = createConstant(1, bits);
  ExprRef e0 = createConstant(0, bits);
  return createIte(e, e1, e0);
}

ExprRef ExprBuilder::createConcat(std::list<ExprRef> exprs) {
  assert(!exprs.empty());
  auto it = exprs.begin();

  // get a first element from the list
  ExprRef e = *it;
  it++;

  for (; it != exprs.end(); it++)
    e = createConcat(e, *it);

  return e;
}

ExprRef ExprBuilder::createLAnd(std::list<ExprRef> exprs) {
  assert(!exprs.empty());
  auto it = exprs.begin();

  // get a first element from the list
  ExprRef e = *it;
  it++;

  for (; it != exprs.end(); it++)
    e = createLAnd(e, *it);

  return e;
}

ExprRef ExprBuilder::createTrunc(ExprRef e, UINT32 bits) {
  return createExtract(e, 0, bits);
}

ExprRef BaseExprBuilder::createRead(ADDRINT off) {
  //printf("THX on createRead: off = %d\n", off);
  static std::vector<ExprRef> cache;
  if (off >= cache.size())
    cache.resize(off + 1);

  if (cache[off] == NULL)
    cache[off] = std::make_shared<ReadExpr>(off);

  return cache[off];
}

ExprRef BaseExprBuilder::createExtract(ExprRef e, UINT32 index, UINT32 bits)
{
  if (bits == e->bits())
    return e;
  ExprRef ref = std::make_shared<ExtractExpr>(e, index, bits);
  addUses(ref);
  return ref;
}

ExprRef
CacheExprBuilder::findOrInsert(ExprRef new_expr) {
  if (ExprRef cached = findInCache(new_expr))
    return cached;
  QSYM_ASSERT(new_expr != NULL);
  insertToCache(new_expr);
  return new_expr;
}

void CacheExprBuilder::insertToCache(ExprRef e) {
  cache_.insert(e);
}

ExprRef CacheExprBuilder::findInCache(ExprRef e) {
  return cache_.find(e);
}

ExprRef CommutativeExprBuilder::createSub(ExprRef l, ExprRef r)
{
  NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  if (nce_l != NULL && ce_r != NULL) {
    // X - C_0 = -C_0 + X
    return createAdd(createNeg(ce_r), nce_l);
  }
  else
    return ExprBuilder::createSub(l, r);
}

ExprRef CommonSimplifyExprBuilder::createConcat(ExprRef l, ExprRef r) {
  // C(E(e, x, y), E(e, y, z)) => E(e, x, z)
  if (auto ee_l = castAs<ExtractExpr>(l)) {
    if (auto ee_r = castAs<ExtractExpr>(r)) {
      if (ee_l->expr() == ee_r->expr()
          && ee_r->index() + ee_r->bits() == ee_l->index()) {
        return createExtract(ee_l->expr(), ee_r->index(), ee_r->bits() + ee_l->bits());
      }
    }
  }

  // C(E(Ext(e), e->bits(), bits), e) == E(Ext(e), 0, e->bits() + bits)
  if (auto ee_l = castAs<ExtractExpr>(l)) {
    if (auto ext = castAs<ExtExpr>(ee_l->expr())) {
      if (ee_l->index() == r->bits()
          && equalShallowly(*ext->expr(), *r)) {
        // Here we used equalShallowly
        // because same ExtractExpr can have different addresses,
        // but using deep comparison is expensive
        return createExtract(ee_l->expr(), 0, ee_l->bits() + r->bits());
      }
    }
  }

  return ExprBuilder::createConcat(l, r);
}

ExprRef CommonSimplifyExprBuilder::createExtract(
    ExprRef e, UINT32 index, UINT32 bits) {
  if (auto ce = castAs<ConcatExpr>(e)) {
    // skips right part
    if (index >= ce->getRight()->bits())
      return createExtract(ce->getLeft(), index - ce->getRight()->bits(), bits);

    // skips left part
    if (index + bits <= ce->getRight()->bits())
      return createExtract(ce->getRight(), index, bits);

    // E(C(C_0,y)) ==> C(E(C_0), E(y))
    if (ce->getLeft()->isConstant()) {
      return createConcat(
          createExtract(ce->getLeft(), 0, bits - ce->getRight()->bits() + index),
          createExtract(ce->getRight(), index, ce->getRight()->bits() - index));
    }
  }
  else if (auto ee = castAs<ExtExpr>(e)) {
    // E(Ext(x), i, b) && len(x) >= i + b == E(x, i, b)
    if (ee->expr()->bits() >= index + bits)
      return createExtract(ee->expr(), index, bits);

    // E(ZExt(x), i, b) && len(x) < i == 0
    if (ee->kind() == ZExt
        && index >= ee->expr()->bits())
      return createConstant(0, bits);
  }
  else if (auto ee = castAs<ExtractExpr>(e)) {
    // E(E(x, i1, b1), i2, b2) == E(x, i1 + i2, b2)
    return createExtract(ee->expr(), ee->index() + index, bits);
  }

  if (index == 0 && e->bits() == bits)
    return e;
  return ExprBuilder::createExtract(e, index, bits);
}

ExprRef CommonSimplifyExprBuilder::createZExt(
    ExprRef e, UINT32 bits) {
  // allow shrinking
  if (e->bits() > bits)
    return createExtract(e, 0, bits);
  if (e->bits() == bits)
    return e;
  return ExprBuilder::createZExt(e, bits);
}

ExprRef CommonSimplifyExprBuilder::createAdd(ExprRef l, ExprRef r)
{
  if (isZero(l))
    return r;

  return ExprBuilder::createAdd(l, r);
}

ExprRef CommonSimplifyExprBuilder::createMul(ExprRef l, ExprRef r) {
  NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  // 0 * X ==> 0
  if (isZero(l))
    return l;

  // 1 * X ==> X
  if (isOne(l))
    return r;

  return ExprBuilder::createMul(l, r);
}

ExprRef CommonSimplifyExprBuilder::simplifyAnd(ExprRef l, ExprRef r) {
  // l & 0 ==> 0
  if (isZero(l))
    return l;

  // l & 11...1b ==> l;
  if (isAllOnes(l))
    return r;

  return NULL;
}

ExprRef CommonSimplifyExprBuilder::createAnd(ExprRef l, ExprRef r)
{
  if (ExprRef simplified = simplifyAnd(l, r))
    return simplified;

  // 0x00ff0000  & 0xaabbccdd = 0x00bb0000
  if (auto const_l = castAs<ConstantExpr>(l)) {
    if (auto concat_r = castAs<ConcatExpr>(r)) {
      ExprRef r_left = concat_r->getLeft();
      ExprRef r_right = concat_r->getRight();
      ExprRef l_left = createExtract(l, r_right->bits(), r_left->bits());

      if (ExprRef and_left = simplifyAnd(l_left, r_left)) {
        return createConcat(
            and_left,
            createAnd(
              createExtract(l, 0,  r_right->bits()),
              r_right));
      }
    }
  }

  return ExprBuilder::createAnd(l, r);
}

ExprRef CommonSimplifyExprBuilder::simplifyOr(ExprRef l, ExprRef r) {
  // 0 | X ==> 0
  if (isZero(l))
    return r;

  // 111...1b | X ==> 111...1b
  if (isAllOnes(l))
    return l;

  return NULL;
}

ExprRef CommonSimplifyExprBuilder::createOr(ExprRef l, ExprRef r) {
  if (ExprRef simplified = simplifyOr(l, r))
    return simplified;

  if (auto const_l = castAs<ConstantExpr>(l)) {
    if (auto concat_r = castAs<ConcatExpr>(r)) {
      ExprRef r_left = concat_r->getLeft();
      ExprRef r_right = concat_r->getRight();
      ExprRef l_left = createExtract(l, r_right->bits(), r_left->bits());

      if (ExprRef and_left = simplifyOr(l_left, r_left)) {
        return createConcat(
            and_left,
            createOr(
              createExtract(l, 0,  r_right->bits()),
              r_right));
      }
    }
  }

  return ExprBuilder::createOr(l, r);
}

ExprRef CommonSimplifyExprBuilder::simplifyXor(ExprRef l, ExprRef r) {
  // 0 ^ X ==> X
  if (isZero(l))
    return r;

  return NULL;
}

ExprRef CommonSimplifyExprBuilder::createXor(ExprRef l, ExprRef r) {
  if (ExprRef simplified = simplifyXor(l, r))
    return simplified;

  if (auto const_l = castAs<ConstantExpr>(l)) {
    if (auto concat_r = castAs<ConcatExpr>(r)) {
      ExprRef r_left = concat_r->getLeft();
      ExprRef r_right = concat_r->getRight();
      ExprRef l_left = createExtract(l, r_right->bits(), r_left->bits());

      if (ExprRef and_left = simplifyXor(l_left, r_left)) {
        return createConcat(
            and_left,
            createXor(
              createExtract(l, 0,  r_right->bits()),
              r_right));
      }
    }
  }

  return ExprBuilder::createXor(l, r);
}

ExprRef CommonSimplifyExprBuilder::createShl(ExprRef l, ExprRef r) {
  if (isZero(l))
    return l;

  if (ConstantExprRef ce_r = castAs<ConstantExpr>(r)) {
    ADDRINT rval = ce_r->value().getLimitedValue();
    if (rval == 0)
      return l;

    // l << larger_than_l_size == 0
    if (rval >= l->bits())
      return createConstant(0, l->bits());

    // from z3: (bvshl x k) -> (concat (extract [n-1-k:0] x) bv0:k)
    // but byte granuality
    if (rval % CHAR_BIT == 0) {
      ExprRef zero = createConstant(0, rval);
      ExprRef partial = createExtract(l, 0, l->bits() - rval);
      return createConcat(partial, zero);
    }
  }

  return ExprBuilder::createShl(l, r);
}

ExprRef CommonSimplifyExprBuilder::createLShr(ExprRef l, ExprRef r) {
  if (isZero(l))
    return l;

  if (ConstantExprRef ce_r = castAs<ConstantExpr>(r)) {
    ADDRINT rval = ce_r->value().getLimitedValue();
    if (rval == 0)
      return l;

    // l << larger_than_l_size == 0
    if (rval >= l->bits())
      return createConstant(0, l->bits());

    // from z3: (bvlshr x k) -> (concat bv0:k (extract [n-1:k] x))
    // but byte granuality
    if (rval % CHAR_BIT == 0) {
      ExprRef zero = createConstant(0, rval);
      ExprRef partial = createExtract(l, rval, l->bits() - rval);
      return createConcat(zero, partial);
    }
  }

  return ExprBuilder::createLShr(l, r);
}

ExprRef CommonSimplifyExprBuilder::createAShr(ExprRef l, ExprRef r) {
  if (ConstantExprRef ce_r = castAs<ConstantExpr>(r)) {
    ADDRINT rval = ce_r->value().getLimitedValue();
    if (rval == 0)
      return l;
  }

  return ExprBuilder::createAShr(l, r);
}

ExprRef CommonSimplifyExprBuilder::createEqual(ExprRef l, ExprRef r) {
  NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  if (auto be_l = castAs<BoolExpr>(l))
    return (be_l->value()) ? r : createLNot(r);

  return ExprBuilder::createEqual(l, r);
}

ExprRef ConstantFoldingExprBuilder::createDistinct(ExprRef l, ExprRef r) {
  ConstantExprRef ce_l = castAs<ConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  if (ce_l != NULL && ce_r != NULL) {
    QSYM_ASSERT(l->bits() == r->bits());
    return createBool(ce_l->value() != ce_r->value());
  }

  BoolExprRef be0 = castAs<BoolExpr>(l);
  BoolExprRef be1 = castAs<BoolExpr>(r);

  if (be0 != NULL && be1 != NULL) {
    return createBool(be0->value() != be1->value());
  }

  return ExprBuilder::createDistinct(l, r);
}

ExprRef ConstantFoldingExprBuilder::createEqual(ExprRef l, ExprRef r) {
  ConstantExprRef ce_l = castAs<ConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  if (ce_l != NULL && ce_r != NULL) {
    QSYM_ASSERT(l->bits() == r->bits());
    return createBool(ce_l->value() == ce_r->value());
  }

  BoolExprRef be0 = castAs<BoolExpr>(l);
  BoolExprRef be1 = castAs<BoolExpr>(r);

  if (be0 != NULL && be1 != NULL)
    return createBool(be0->value() == be1->value());

  return ExprBuilder::createEqual(l, r);
}

ExprRef ConstantFoldingExprBuilder::createLAnd(ExprRef l, ExprRef r) {
  BoolExprRef be0 = castAs<BoolExpr>(l);
  BoolExprRef be1 = castAs<BoolExpr>(r);

  if (be0 != NULL && be1 != NULL)
    return createBool(be0->value() && be1->value());
  else
    return ExprBuilder::createLAnd(l, r);
}

ExprRef ConstantFoldingExprBuilder::createLOr(ExprRef l, ExprRef r) {
  BoolExprRef be0 = castAs<BoolExpr>(l);
  BoolExprRef be1 = castAs<BoolExpr>(r);

  if (be0 != NULL && be1 != NULL)
    return createBool(be0->value() || be1->value());
  else
    return ExprBuilder::createLOr(l, r);
}

ExprRef ConstantFoldingExprBuilder::createConcat(ExprRef l, ExprRef r) {
  // C(l, r) && l == constant && r == constant  => l << r_bits | r
  ConstantExprRef ce_l = castAs<ConstantExpr>(l);
  ConstantExprRef ce_r = castAs<ConstantExpr>(r);

  if (ce_l != NULL && ce_r != NULL) {
    UINT32 bits = ce_l->bits() + ce_r->bits();
    llvm::APInt lval = ce_l->value().zext(bits);
    llvm::APInt rval = ce_r->value().zext(bits);
    llvm::APInt res = (lval << ce_r->bits()) | rval;
    return createConstant(res, bits);
  }
  else
    return ExprBuilder::createConcat(l, r);
}

ExprRef ConstantFoldingExprBuilder::createIte(ExprRef expr_cond,
    ExprRef expr_true, ExprRef expr_false) {
  if (auto be = castAs<BoolExpr>(expr_cond)) {
    if (be->value())
      return expr_true;
    else
      return expr_false;
  }

  return ExprBuilder::createIte(expr_cond, expr_true, expr_false);
}

ExprRef ConstantFoldingExprBuilder::createExtract(
    ExprRef e, UINT32 index, UINT32 bits) {
  if (ConstantExprRef ce = castAs<ConstantExpr>(e)) {
    llvm::APInt v = ce->value().lshr(index);
    v = v.zextOrTrunc(bits);
    return createConstant(v, bits);
  }
  else
    return ExprBuilder::createExtract(e, index, bits);
}

ExprRef ConstantFoldingExprBuilder::createZExt(ExprRef e, UINT32 bits) {
  if (ConstantExprRef ce = castAs<ConstantExpr>(e)) {
    return createConstant(ce->value().zext(bits), bits);
  }
  else
    return ExprBuilder::createZExt(e, bits);
}

ExprRef ConstantFoldingExprBuilder::createSExt(ExprRef e, UINT32 bits) {
  if (ConstantExprRef ce = castAs<ConstantExpr>(e)) {
    return createConstant(ce->value().sext(bits), bits);
  }
  else
    return ExprBuilder::createSExt(e, bits);
}

ExprRef ConstantFoldingExprBuilder::createNeg(ExprRef e) {
  if (ConstantExprRef ce = castAs<ConstantExpr>(e))
    return createConstant(-ce->value(), ce->bits());
  else
    return ExprBuilder::createNeg(e);
}

ExprRef ConstantFoldingExprBuilder::createNot(ExprRef e) {
  if (ConstantExprRef ce = castAs<ConstantExpr>(e))
    return createConstant(~ce->value(), ce->bits());
  else
    return ExprBuilder::createNot(e);
}

ExprRef ConstantFoldingExprBuilder::createLNot(ExprRef e) {
  if (BoolExprRef be = castAs<BoolExpr>(e))
    return createBool(!be->value());
  else
    return ExprBuilder::createLNot(e);
}

ExprRef SymbolicExprBuilder::createConcat(ExprRef l, ExprRef r) {
  // C(l, C(x, y)) && l, x == constant => C(l|x, y)
  if (auto ce = castAs<ConcatExpr>(r)) {
    ConstantExprRef ce_l = castAs<ConstantExpr>(l);
    ConstantExprRef ce_x = castAs<ConstantExpr>(ce->getLeft());
    if (ce_l != NULL && ce_x != NULL)
      return createConcat(createConcat(ce_l, ce_x), ce->getRight());
  }

  // C(C(x ,y), z) => C(x, C(y, z))
  if (auto ce = castAs<ConcatExpr>(l)) {
    return createConcat(l->getLeft(),
        createConcat(l->getRight(), r));
  }

  return ExprBuilder::createConcat(l, r);
}

ExprRef SymbolicExprBuilder::createExtract(ExprRef op, UINT32 index, UINT32 bits) {
  // Only byte-wise simplification
  if (index == 0
      && bits % 8 == 0
      && canEvaluateTruncated(op, bits)) {
      if (ExprRef e = evaluateInDifferentType(this, op, index, bits))
        return e;
  }
  return ExprBuilder::createExtract(op, index, bits);
}

ExprRef SymbolicExprBuilder::simplifyExclusiveExpr(ExprRef l, ExprRef r) {
  // From z3
  // (bvor (concat x #x00) (concat #x00 y)) --> (concat x y)
  // (bvadd (concat x #x00) (concat #x00 y)) --> (concat x y)

  for (UINT i = 0; i < l->bits(); i++)
    if (!isZeroBit(l, i) && !isZeroBit(r, i))
      return NULL;

  std::list<ExprRef> exprs;
  UINT32 i = 0;
  while (i < l->bits()) {
    UINT32 prev = i;
    while (i < l->bits() && isZeroBit(l, i))
      i++;
    if (i != prev)
      exprs.push_front(createExtract(r, prev, i - prev));
    prev = i;
    while (i < r->bits() && isZeroBit(r, i))
      i++;
    if (i != prev)
      exprs.push_front(createExtract(l, prev, i - prev));
  }

  return ExprBuilder::createConcat(exprs);
}

ExprRef SymbolicExprBuilder::createAdd(ExprRef l, ExprRef r) {
  if (ExprRef e = simplifyExclusiveExpr(l, r))
    return e;

  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (ConstantExprRef ce_l = castAs<ConstantExpr>(l))
      return createAdd(ce_l, nce_r);
    else {
      NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
      QSYM_ASSERT(nce_l != NULL);
      return createAdd(nce_l, nce_r);
    }
  }
  else
    return ExprBuilder::createAdd(l, r);
}

ExprRef SymbolicExprBuilder::createAdd(ConstantExprRef l, NonConstantExprRef r) {
  switch (r->kind()) {
    case Add: {
      // C_0 + (C_1 + X) ==> (C_0 + C_1) + X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createAdd(createAdd(l, CE), r->getSecondChild());
      // C_0 + (X + C_1) ==> (C_0 + C_1) + X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(createAdd(l, CE), r->getFirstChild());
      break;
    }

    case Sub: {
      // C_0 + (C_1 - X) ==> (C_0 + C1) - X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createSub(createAdd(l, CE), r->getSecondChild());
      // C_0 + (X - C_1) ==> (C_0 - C1) + X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(createSub(l, CE), r->getFirstChild());
      break;
    }
    default:
      break;
  }

  return ExprBuilder::createAdd(l, r);
}

ExprRef SymbolicExprBuilder::createAdd(NonConstantExprRef l, NonConstantExprRef r) {
  if (l == r) {
    // l + l ==> 2 * l
    ExprRef two = createConstant(2, l->bits());
    return createMul(two, l);
  }

  switch (l->kind()) {
    default: break;
    case Add:
    case Sub: {
      // (X + Y) + Z ==> Z + (X + Y)
      // Or (X - Y) + Z ==> Z + (X - Y)
      std::swap(l, r);
    }
  }

  switch (r->kind()) {
    case Add: {
      // X + (C_0 + Y) ==> C_0 + (X + Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createAdd(CE, createAdd(l, r->getSecondChild()));
      // X + (Y + C_0) ==> C_0 + (X + Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(CE, createAdd(l, r->getFirstChild()));
      break;
    }

    case Sub: {
      // X + (C_0 - Y) ==> C_0 + (X - Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createAdd(CE, createSub(l, r->getSecondChild()));
      // X + (Y - C_0) ==> -C_0 + (X + Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(createNeg(CE), createAdd(l, r->getFirstChild()));
      break;
    }
    default:
      break;
  }

  return ExprBuilder::createAdd(l, r);
}

ExprRef SymbolicExprBuilder::createSub(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (ConstantExprRef ce_l = castAs<ConstantExpr>(l))
      return createSub(ce_l, nce_r);
    else {
      NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
      QSYM_ASSERT(nce_l != NULL);
      return createSub(nce_l, nce_r);
    }
  }
  else
    return ExprBuilder::createSub(l, r);
}

ExprRef SymbolicExprBuilder::createSub(ConstantExprRef l, NonConstantExprRef r) {
  switch (r->kind()) {
    case Add: {
      // C_0 - (C_1 + X) ==> (C_0 - C1) - X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createSub(createSub(l, CE), r->getSecondChild());
      // C_0 - (X + C_1) ==> (C_0 - C1) - X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createSub(createSub(l, CE), r->getFirstChild());
      break;
    }

    case Sub: {
      // C_0 - (C_1 - X) ==> (C_0 - C1) + X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild())) {
        return createAdd(createSub(l, CE), r->getSecondChild());
      }
      // C_0 - (X - C_1) ==> (C_0 + C1) - X
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild())) {
        return createSub(createAdd(l, CE), r->getFirstChild());
      }
      break;
    }
    default:
      break;
  }

  return ExprBuilder::createSub(l, r);
}

ExprRef SymbolicExprBuilder::createSub(
    NonConstantExprRef l,
    NonConstantExprRef r) {
  // X - X ==> 0
  if (l == r)
    return createConstant(0, l->bits());

  switch (l->kind()) {
    default: break;
    case Add:
      if (l->getChild(0)->isConstant()) {
        // (C + Y) - Z ==> C + (Y - Z)
        return createAdd(l->getChild(0),
            createSub(l->getChild(1), r));
      }
    case Sub: {
      if (l->getChild(0)->isConstant()) {
        // (C - Y) - Z ==> C - (Y + Z)
        return createSub(l->getChild(0),
            createAdd(l->getChild(1), r));
      }
    }
  }

  switch (r->kind()) {
    case Add: {
      // X - (C_0 + Y) ==> -C_0 + (X - Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createAdd(createNeg(CE), createSub(l, r->getSecondChild()));
      // X - (Y + C_0) ==> -C_0 + (X - Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(createNeg(CE), createSub(l, r->getFirstChild()));
      break;
    }

    case Sub: {
      // X - (C_0 - Y) ==> -C_0 + (X + Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getFirstChild()))
        return createAdd(createNeg(CE), createAdd(l, r->getSecondChild()));
      // X - (Y - C_0) ==> C_0 + (X - Y)
      if (ConstantExprRef CE = castAs<ConstantExpr>(r->getSecondChild()))
        return createAdd(CE, createSub(l, r->getFirstChild()));
      break;
    }
    default:
      break;
  }
  return ExprBuilder::createSub(l, r);
}

ExprRef SymbolicExprBuilder::createMul(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (ConstantExprRef ce_l = castAs<ConstantExpr>(l))
      return createMul(ce_l, nce_r);
  }

  return ExprBuilder::createMul(l, r);
}

ExprRef SymbolicExprBuilder::createMul(ConstantExprRef l, NonConstantExprRef r) {
  // C_0 * (C_1 * x) ==> (C_0 * C_1) * x
  if (auto me = castAs<MulExpr>(r)) {
    if (ConstantExprRef ce = castAs<ConstantExpr>(r->getLeft())) {
      return createMul(createMul(l, ce), r->getRight());
    }
  }

  // C_0 * (C_1 + x) ==> C_0 * C_1 + C_0 * x
  if (auto ae = castAs<AddExpr>(r)) {
    if (ConstantExprRef ce = castAs<ConstantExpr>(r->getLeft())) {
      return createAdd(createMul(l, ce), createMul(l, r->getRight()));
    }
  }

  return ExprBuilder::createMul(l, r);
}

ExprRef SymbolicExprBuilder::createSDiv(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_l = castAs<NonConstantExpr>(l)) {
    if (ConstantExprRef ce_r = castAs<ConstantExpr>(r))
      return createSDiv(nce_l, ce_r);
  }

  return ExprBuilder::createSDiv(l, r);
}

ExprRef SymbolicExprBuilder::createSDiv(NonConstantExprRef l, ConstantExprRef r) {
  // x /s -1 = -x
  if (r->isAllOnes())
    return createNeg(l);

  // SExt(x) /s y && x->bits() >= y->getActiveBits() ==> SExt(x /s y)
  // Only works when y != -1, but already handled by the above statement
  if (auto sext_l = castAs<SExtExpr>(l)) {
    ExprRef x = sext_l->expr();
    if (x->bits() >= r->getActiveBits()) {
      return createSExt(
              createSDiv(x,
                createExtract(r, 0, x->bits())),
              l->bits());
    }
  }

  // TODO: add overflow check
  // (x / C_0) / C_1 = (x / (C_0 * C_1))
  if (auto se = castAs<SDivExpr>(l)) {
    if (ConstantExprRef ce = castAs<ConstantExpr>(l->getRight())) {
      return createSDiv(l->getLeft(), createMul(ce, r));
    }
  }
  return ExprBuilder::createSDiv(l, r);
}

ExprRef SymbolicExprBuilder::createUDiv(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_l = castAs<NonConstantExpr>(l)) {
    if (ConstantExprRef ce_r = castAs<ConstantExpr>(r))
      return createUDiv(nce_l, ce_r);
  }

  return ExprBuilder::createUDiv(l, r);
}

ExprRef SymbolicExprBuilder::createUDiv(NonConstantExprRef l, ConstantExprRef r) {
  // C(0, x) / y && y->getActiveBits() <= x->bits()
  // == C(0, x/E(y, 0, x->bits()))
  if (auto ce = castAs<ConcatExpr>(l)) {
    ExprRef ce_l = ce->getLeft();
    ExprRef ce_r = ce->getRight();
    if (ce_l->isZero()) {
      if (r->getActiveBits() <= ce_r->bits()) {
        ExprRef e = createConcat(
            ce_l,
            createUDiv(
              ce_r,
              createExtract(r, 0, ce_r->bits())));
        return e;
      }
    }
  }

  // TODO: add overflow check
  // (x / C_0) / C_1 = (x / (C_0 * C_1))
  if (auto se = castAs<UDivExpr>(l)) {
    if (ConstantExprRef ce = castAs<ConstantExpr>(l->getRight())) {
      return createUDiv(l->getLeft(), createMul(ce, r));
    }
  }
  return ExprBuilder::createUDiv(l, r);
}

ExprRef SymbolicExprBuilder::createAnd(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (ConstantExprRef ce_l = castAs<ConstantExpr>(l))
      return createAnd(ce_l, nce_r);
    else {
      NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
      QSYM_ASSERT(nce_l != NULL);
      return createAnd(nce_l, nce_r);
    }
  }
  else
    return ExprBuilder::createAnd(l, r);
}

ExprRef SymbolicExprBuilder::createAnd(ConstantExprRef l, NonConstantExprRef r) {
  return ExprBuilder::createAnd(l, r);
}

ExprRef SymbolicExprBuilder::createAnd(NonConstantExprRef l, NonConstantExprRef r) {
  // A & A  ==> A
  if (l == r)
    return l;

  // C(x, y) & C(w, v) ==> C(x & w, y & v)
  if (auto ce_l = castAs<ConcatExpr>(l)) {
    if (auto ce_r = castAs<ConcatExpr>(r)) {
      if (ce_l->getLeft()->bits() == ce_r->getLeft()->bits()) {
        // right bits are same, because it is binary operation
        return createConcat(
            createAnd(l->getLeft(), r->getLeft()),
            createAnd(l->getRight(), r->getRight()));
      }
    }
  }
  return ExprBuilder::createAnd(l, r);
}

ExprRef SymbolicExprBuilder::createOr(ExprRef l, ExprRef r) {
 if (ExprRef e = simplifyExclusiveExpr(l, r))
    return e;

  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (ConstantExprRef ce_l = castAs<ConstantExpr>(l))
      return createOr(ce_l, nce_r);
    else {
      NonConstantExprRef nce_l = castAs<NonConstantExpr>(l);
      QSYM_ASSERT(nce_l != NULL);
      return createOr(nce_l, nce_r);
    }
  }
  else
    return ExprBuilder::createOr(l, r);
}

ExprRef SymbolicExprBuilder::createOr(ConstantExprRef l, NonConstantExprRef r) {
  if (auto ce = castAs<ConcatExpr>(r)) {
    // C_0 | C(x, y) ==> C(C_0 | x, C_0 | y)
    // TODO: only for constant case
    return createConcat(
        createOr(
          createExtract(l, ce->getRight()->bits(), ce->getLeft()->bits()),
          ce->getLeft()),
        createOr(
          createExtract(l, 0, ce->getRight()->bits()),
          ce->getRight()));
  }

  return ExprBuilder::createOr(l, r);
}

ExprRef SymbolicExprBuilder::createOr(NonConstantExprRef l, NonConstantExprRef r) {
  // A | A = A
  if (l == r)
    return l;

  // C(x, y) & C(w, v) == C(x | w, y | v)
  if (auto ce_l = castAs<ConcatExpr>(l)) {
    if (auto ce_r = castAs<ConcatExpr>(r)) {
      if (ce_l->getLeft()->bits() == ce_r->getLeft()->bits()) {
        // right bits are same, because it is binary operation
        return createConcat(
            createOr(l->getLeft(), r->getLeft()),
            createOr(l->getRight(), r->getRight()));
      }
    }
  }

  return ExprBuilder::createOr(l, r);
}

ExprRef SymbolicExprBuilder::createXor(ExprRef l, ExprRef r) {
  if (NonConstantExprRef nce_r = castAs<NonConstantExpr>(r)) {
    if (NonConstantExprRef nce_l = castAs<NonConstantExpr>(l)) {
      return createXor(nce_l, nce_r);
    }
  }

  return ExprBuilder::createXor(l, r);
}

ExprRef SymbolicExprBuilder::createXor(NonConstantExprRef l, NonConstantExprRef r) {
  if (l == r)
    return createConstant(0, l->bits());
  else
    return ExprBuilder::createXor(l, r);
}

ExprRef SymbolicExprBuilder::createEqual(ExprRef l, ExprRef r) {
  if (l == r)
    return createTrue();

  return ExprBuilder::createEqual(l, r);
}

ExprRef SymbolicExprBuilder::createDistinct(ExprRef l, ExprRef r) {
  return createLNot(createEqual(l, r));
}

ExprRef SymbolicExprBuilder::createLOr(ExprRef l, ExprRef r) {
  if (auto BE_L = castAs<BoolExpr>(l))
    return BE_L->value() ? createTrue() : r;

  if (auto BE_R = castAs<BoolExpr>(r))
    return BE_R->value() ? createTrue() : l;

  return ExprBuilder::createLOr(l, r);
}

ExprRef SymbolicExprBuilder::createLAnd(ExprRef l, ExprRef r) {
  if (auto BE_L = castAs<BoolExpr>(l))
    return BE_L->value() ? r : createFalse();

  if (auto BE_R = castAs<BoolExpr>(r))
    return BE_R->value() ? l : createFalse();

  return ExprBuilder::createLAnd(l, r);
}

ExprRef SymbolicExprBuilder::createLNot(ExprRef e) {
  if (auto BE = castAs<BoolExpr>(e))
    return createBool(!BE->value());
  if (auto NE = castAs<LNotExpr>(e))
    return NE->expr();
  return ExprBuilder::createLNot(e);
}

ExprRef SymbolicExprBuilder::createIte(
    ExprRef expr_cond,
    ExprRef expr_true,
    ExprRef expr_false) {
  if (auto BE = castAs<BoolExpr>(expr_cond))
    return BE->value() ? expr_true : expr_false;
  if (auto NE = castAs<LNotExpr>(expr_cond))
    return createIte(NE->expr(), expr_false, expr_true);
  return ExprBuilder::createIte(expr_cond, expr_true, expr_false);
}

ExprBuilder* PruneExprBuilder::create() {
  ExprBuilder* base = new BaseExprBuilder();
  ExprBuilder* commu = new CommutativeExprBuilder();
  ExprBuilder* common = new CommonSimplifyExprBuilder();
  ExprBuilder* const_folding = new ConstantFoldingExprBuilder();
  ExprBuilder* symbolic = new SymbolicExprBuilder();
  ExprBuilder* cache = new CacheExprBuilder();
  ExprBuilder* fuzz = new PruneExprBuilder();

  // commu -> symbolic -> common -> constant folding -> fuzz -> cache -> base
  commu->setNext(symbolic);
  symbolic->setNext(common);
  common->setNext(const_folding);
  const_folding->setNext(fuzz);
  fuzz->setNext(cache);
  cache->setNext(base);
  return commu;
}

#define DEFINE_EXPR_BUILDER_CREATE(_name, _args, ...) \
ExprRef ExprBuilder::_name(__VA_ARGS__) \
{ \
  return next_->_name _args; \
}

DEFINE_EXPR_BUILDER_CREATE(createBool, (b), bool b);
DEFINE_EXPR_BUILDER_CREATE(createConstant, (value, bits), ADDRINT value, UINT32 bits);
DEFINE_EXPR_BUILDER_CREATE(createConstant, (value, bits), llvm::APInt value, UINT32 bits);
DEFINE_EXPR_BUILDER_CREATE(createRead, (off), ADDRINT off);
DEFINE_EXPR_BUILDER_CREATE(createConcat, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createExtract, (e, index, bits), ExprRef e, UINT32 index, UINT32 bits);
DEFINE_EXPR_BUILDER_CREATE(createZExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_EXPR_BUILDER_CREATE(createSExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_EXPR_BUILDER_CREATE(createAdd, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSub, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createMul, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createUDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createURem, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSRem, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createNeg, (e), ExprRef e);
DEFINE_EXPR_BUILDER_CREATE(createNot, (e), ExprRef e);
DEFINE_EXPR_BUILDER_CREATE(createAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createOr, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createXor, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createShl, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createLShr, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createAShr, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createEqual, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createDistinct, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createUlt, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createUle, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createUgt, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createUge, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSlt, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSle, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSgt, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createSge, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createLOr, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createLAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_EXPR_BUILDER_CREATE(createLNot, (e), ExprRef e);
DEFINE_EXPR_BUILDER_CREATE(createIte, (expr_cond, expr_true, expr_false), ExprRef expr_cond, ExprRef expr_true, ExprRef expr_false);
#undef DEFINE_EXPR_BUILDER_CREATE

#define DEFINE_BINARY_EXPR_CASE(kind) \
  case kind: \
    return create##kind(l, r);

ExprRef ExprBuilder::createBinaryExpr(Kind kind, ExprRef l, ExprRef r)
{
  switch (kind) {
DEFINE_BINARY_EXPR_CASE(Add)
DEFINE_BINARY_EXPR_CASE(Sub)
DEFINE_BINARY_EXPR_CASE(Mul)
DEFINE_BINARY_EXPR_CASE(UDiv)
DEFINE_BINARY_EXPR_CASE(SDiv)
DEFINE_BINARY_EXPR_CASE(URem)
DEFINE_BINARY_EXPR_CASE(SRem)
DEFINE_BINARY_EXPR_CASE(And)
DEFINE_BINARY_EXPR_CASE(Or)
DEFINE_BINARY_EXPR_CASE(Xor)
DEFINE_BINARY_EXPR_CASE(Shl)
DEFINE_BINARY_EXPR_CASE(LShr)
DEFINE_BINARY_EXPR_CASE(AShr)
DEFINE_BINARY_EXPR_CASE(Equal)
DEFINE_BINARY_EXPR_CASE(Distinct)
DEFINE_BINARY_EXPR_CASE(Ult)
DEFINE_BINARY_EXPR_CASE(Ule)
DEFINE_BINARY_EXPR_CASE(Ugt)
DEFINE_BINARY_EXPR_CASE(Uge)
DEFINE_BINARY_EXPR_CASE(Slt)
DEFINE_BINARY_EXPR_CASE(Sle)
DEFINE_BINARY_EXPR_CASE(Sgt)
DEFINE_BINARY_EXPR_CASE(Sge)
DEFINE_BINARY_EXPR_CASE(LOr)
DEFINE_BINARY_EXPR_CASE(LAnd)
  default:
    LOG_FATAL("Non-binary expr: " + std::to_string(kind) + "\n");
    return NULL;
  }
}
#undef DEFINE_BINARY_EXPR_CASE

ExprRef ExprBuilder::createUnaryExpr(Kind kind, ExprRef e) {
switch (kind) {
  case Not:
    return createNot(e);
  case Neg:
    return createNeg(e);
  case LNot:
    return createLNot(e);
  default:
    LOG_FATAL("Non-unary expr: " + std::to_string(kind) + "\n");
    return NULL;
  }
}

#define DEFINE_BASEEXPRBUILDER(_name, _args, ...) \
ExprRef BaseExprBuilder::create##_name (__VA_ARGS__){ \
ExprRef ref = std::make_shared<_name##Expr> _args; \
addUses(ref); \
return ref; \
}

DEFINE_BASEEXPRBUILDER(Bool, (b), bool b);
DEFINE_BASEEXPRBUILDER(Constant, (value, bits), ADDRINT value, UINT32 bits);
DEFINE_BASEEXPRBUILDER(Constant, (value, bits), llvm::APInt value, UINT32 bits);
DEFINE_BASEEXPRBUILDER(Concat, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(ZExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_BASEEXPRBUILDER(SExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_BASEEXPRBUILDER(Add, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Sub, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Mul, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(UDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(SDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(URem, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(SRem, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Neg, (e), ExprRef e);
DEFINE_BASEEXPRBUILDER(Not, (e), ExprRef e);
DEFINE_BASEEXPRBUILDER(And, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Or, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Xor, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Shl, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(LShr, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(AShr, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Equal, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Distinct, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Ult, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Ule, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Ugt, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Uge, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Slt, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Sle, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Sgt, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(Sge, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(LOr, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(LAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_BASEEXPRBUILDER(LNot, (e), ExprRef e);
DEFINE_BASEEXPRBUILDER(Ite, (expr_cond, expr_true, expr_false), ExprRef expr_cond, ExprRef expr_true, ExprRef expr_false);
#undef DEFINE_BASEEXPRBUILDER

#define DEFINE_CACHE_EXPR(_name, _args, ...)\
ExprRef CacheExprBuilder::_name(__VA_ARGS__) { \
  ExprRef new_expr = ExprBuilder::_name _args; \
  return findOrInsert(new_expr); \
}


DEFINE_CACHE_EXPR(createConcat, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createExtract, (e, index, bits), ExprRef e, UINT32 index, UINT32 bits);
DEFINE_CACHE_EXPR(createZExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_CACHE_EXPR(createSExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_CACHE_EXPR(createAdd, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSub, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createMul, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createUDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createURem, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSRem, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createNeg, (e), ExprRef e);
DEFINE_CACHE_EXPR(createNot, (e), ExprRef e);
DEFINE_CACHE_EXPR(createAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createOr, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createXor, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createShl, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createLShr, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createAShr, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createEqual, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createDistinct, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createUlt, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createUle, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createUgt, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createUge, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSlt, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSle, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSgt, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createSge, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createLOr, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createLAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_CACHE_EXPR(createLNot, (e), ExprRef e);
DEFINE_CACHE_EXPR(createIte, (expr_cond, expr_true, expr_false), ExprRef expr_cond, ExprRef expr_true, ExprRef expr_false);
#undef DEFINE_CACHE_EXPR

#define DEFINE_COMMUTATIVE_EXPR_BUILDER(_name, _commut_name) \
ExprRef CommutativeExprBuilder::_name(ExprRef l, ExprRef r) { \
  NonConstantExprRef nce_l = castAs<NonConstantExpr>(l); \
  ConstantExprRef ce_r = castAs<ConstantExpr>(r); \
  if (nce_l != NULL && ce_r != NULL) \
    return _commut_name(ce_r, nce_l); \
  return ExprBuilder::_name(l, r); \
}

#define DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(_name) DEFINE_COMMUTATIVE_EXPR_BUILDER(_name, _name)

DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createAdd);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createMul);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createAnd);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createOr);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createXor);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createEqual);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createDistinct);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createLAnd);
DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME(createLOr);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createUlt, createUgt);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createUle, createUge);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createUgt, createUlt);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createUge, createUle);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createSlt, createSgt);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createSle, createSge);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createSgt, createSlt);
DEFINE_COMMUTATIVE_EXPR_BUILDER(createSge, createSle);
#undef DEFINE_COMMUTATIVE_EXPR_BUILDER_SAME
#undef DEFINE_COMMUTATIVE_EXPR_BUILDER


#define CONST_FOLD_OP_BINARY(_kind, _sym) \
   ce_l->value() _sym ce_r->value()

#define CONST_FOLD_OP_FUNC(_kind, _sym) \
  ce_l->value()._sym(ce_r->value())

#define CONST_FOLD_RET_CONST(_kind, _op, _sym) \
  createConstant( CONST_FOLD_OP_##_op(_kind, _sym) , l->bits());

#define CONST_FOLD_RET_BOOL(_kind, _op, _sym) \
  createBool( CONST_FOLD_OP_##_op(_kind, _sym) );

#define DEFINE_CONST_FOLDING_EXPR_BUILDER(_kind, _ret, _op, _sym) \
ExprRef ConstantFoldingExprBuilder::create##_kind(ExprRef l, ExprRef r) { \
  ConstantExprRef ce_l = castAs<ConstantExpr>(l); \
  ConstantExprRef ce_r = castAs<ConstantExpr>(r); \
 \
  if (ce_l != NULL && ce_r != NULL) { \
    QSYM_ASSERT(l->bits() == r->bits()); \
    return CONST_FOLD_RET_##_ret(_kind, _op, _sym); \
  } \
  else \
    return ExprBuilder::create##_kind(l, r); \
}

DEFINE_CONST_FOLDING_EXPR_BUILDER(Add, CONST, BINARY, +)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Sub, CONST, BINARY, -)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Mul, CONST, BINARY, *)
DEFINE_CONST_FOLDING_EXPR_BUILDER(UDiv, CONST, FUNC, udiv)
DEFINE_CONST_FOLDING_EXPR_BUILDER(SDiv, CONST, FUNC, sdiv)
DEFINE_CONST_FOLDING_EXPR_BUILDER(URem, CONST, FUNC, urem)
DEFINE_CONST_FOLDING_EXPR_BUILDER(SRem, CONST, FUNC, srem)
DEFINE_CONST_FOLDING_EXPR_BUILDER(And, CONST, BINARY, &)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Or, CONST, BINARY, |)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Xor, CONST, BINARY, ^)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Shl, CONST, BINARY, <<)
DEFINE_CONST_FOLDING_EXPR_BUILDER(LShr, CONST, FUNC, lshr)
DEFINE_CONST_FOLDING_EXPR_BUILDER(AShr, CONST, FUNC, ashr)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Ult, BOOL, FUNC, ult)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Ule, BOOL, FUNC, ule)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Ugt, BOOL, FUNC, ugt)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Uge, BOOL, FUNC, uge)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Slt, BOOL, FUNC, slt)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Sle, BOOL, FUNC, sle)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Sgt, BOOL, FUNC, sgt)
DEFINE_CONST_FOLDING_EXPR_BUILDER(Sge, BOOL, FUNC, sge)
#undef DEFINE_CONST_FOLDING_EXPR_BUILDER
#undef CONST_FOLD_OP_FUNC
#undef CONST_FOLD_OP_BINARY
#undef CONST_FOLD_RET_BOOL
#undef CONST_FOLD_RET_CONST

#define DEFINE_PRUNE_EXPR_BUILDER(_name, _args, ...) \
ExprRef PruneExprBuilder::_name(__VA_ARGS__) { \
  ExprRef ref = ExprBuilder::_name _args; \
  g_call_stack_manager.updateBitmap(); \
  if (g_call_stack_manager.isInteresting()) \
    return ref; \
  else \
    return ref->evaluate(); \
}

DEFINE_PRUNE_EXPR_BUILDER(createZExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_PRUNE_EXPR_BUILDER(createSExt, (e, bits), ExprRef e, UINT32 bits);
DEFINE_PRUNE_EXPR_BUILDER(createAdd, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createSub, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createMul, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createUDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createSDiv, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createURem, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createSRem, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createNeg, (e), ExprRef e);
DEFINE_PRUNE_EXPR_BUILDER(createNot, (e), ExprRef e);
DEFINE_PRUNE_EXPR_BUILDER(createAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createOr, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createXor, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createShl, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createLShr, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createAShr, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createLOr, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createLAnd, (l,r), ExprRef l, ExprRef r);
DEFINE_PRUNE_EXPR_BUILDER(createLNot, (e), ExprRef e);
DEFINE_PRUNE_EXPR_BUILDER(createIte, (expr_cond, expr_true, expr_false), ExprRef expr_cond, ExprRef expr_true, ExprRef expr_false);
#undef DEFINE_PRUNE_EXPR_BUILDER

} // namespace qsym
