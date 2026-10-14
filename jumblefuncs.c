/*-------------------------------------------------------------------------
 *
 * jumblefuncs.c
 *	  Helper functions for calculating a plan ID through a "jumble".
 *
 * Portions Copyright (c) 1996-2025, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *	  contrib/pg_stat_plans/jumblefuncs.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/transam.h"
#include "catalog/pg_proc.h"
#include "common/hashfn.h"
#if PG_VERSION_NUM >= 170000
#include "common/hashfn_unstable.h"
#else
#include "compat_16_17/fasthash.h"
#endif
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "nodes/queryjumble.h"
#include "utils/lsyscache.h"
#include "parser/scansup.h"

#include "jumblefuncs.h"

/*
 * We store a fasthash_state in the memory pointed to by jstate->jumble,
 * using streaming fasthash instead of the upstream Jenkins-based buffer
 * approach.  This avoids the 1024-byte buffer, periodic rehashing, and
 * the overhead of hash_any_extended calls.
 */
#define JUMBLE_HASH_STATE(jstate) ((fasthash_state *) (jstate)->jumble)

static JumbleState *InitJumbleInternal(bool record_clocations);
#if PG_VERSION_NUM >= 180000
static void _jumbleElements(JumbleState *jstate, List *elements, Node *node);
static void _jumbleParam(JumbleState *jstate, Node *node);
#endif
static void _jumbleA_Const(JumbleState *jstate, Node *node);
static void _jumbleList(JumbleState *jstate, Node *node);
static void _jumbleVariableSetStmt(JumbleState *jstate, Node *node);
#if PG_VERSION_NUM < 170000
static void _jumbleRangeTblEntry(JumbleState *jstate, Node *node);
#elif PG_VERSION_NUM >= 180000
static void _jumbleRangeTblEntry_eref(JumbleState *jstate,
									  RangeTblEntry *rte,
									  Alias *expr);
#endif

#if PG_VERSION_NUM >= 180000
static void FlushPendingNulls(JumbleState *jstate);
#endif

/*
 * InitJumbleInternal
 *		Allocate a JumbleState object and make it ready to jumble.
 */
static JumbleState *
InitJumbleInternal(bool record_clocations)
{
	JumbleState *jstate;
	fasthash_state *hs;

	jstate = (JumbleState *) palloc(sizeof(JumbleState));

	/* Set up fasthash state for streaming plan jumbling */
	hs = (fasthash_state *) palloc(sizeof(fasthash_state));
	fasthash_init(hs, 0);
	jstate->jumble = (unsigned char *) hs;
	jstate->jumble_len = 0;

	if (record_clocations)
	{
		jstate->clocations_buf_size = 32;
		jstate->clocations = (LocationLen *)
			palloc(jstate->clocations_buf_size * sizeof(LocationLen));
	}
	else
	{
		jstate->clocations_buf_size = 0;
		jstate->clocations = NULL;
	}

	jstate->clocations_count = 0;
	jstate->highest_extern_param_id = 0;
#if PG_VERSION_NUM >= 180000
	jstate->has_squashed_lists = false;
#endif
#if PG_VERSION_NUM >= 180000
	jstate->pending_nulls = 0;
#ifdef USE_ASSERT_CHECKING
	jstate->total_jumble_len = 0;
#endif
#endif

	return jstate;
}

/*
 * Exported initializer for jumble state that allows plugins to hash values and
 * nodes, but does not record constant locations, for now.
 */
JumbleState *
InitJumble(void)
{
	return InitJumbleInternal(false);
}

/*
 * Produce a 64-bit hash from a jumble state.
 */
uint64
HashJumbleState(JumbleState *jstate)
{
#if PG_VERSION_NUM >= 180000
	/* Flush any pending NULLs before doing the final hash */
	if (jstate->pending_nulls > 0)
		FlushPendingNulls(jstate);
#endif

	return fasthash_final64(JUMBLE_HASH_STATE(jstate), jstate->jumble_len);
}

/*
 * AppendJumbleVarlen: Accumulate a variable-length value into the fasthash
 * state, processing it in 8-byte chunks.
 */
static pg_attribute_always_inline void
AppendJumbleVarlen(JumbleState *jstate, const unsigned char *item, Size size)
{
	fasthash_state *hs = JUMBLE_HASH_STATE(jstate);
	Size		orig_size = size;

	Assert(size > 0);

	while (size >= FH_SIZEOF_ACCUM)
	{
		fasthash_accum(hs, (const char *) item, FH_SIZEOF_ACCUM);
		item += FH_SIZEOF_ACCUM;
		size -= FH_SIZEOF_ACCUM;
	}

	if (size > 0)
		fasthash_accum(hs, (const char *) item, size);

	jstate->jumble_len += orig_size;

#if PG_VERSION_NUM >= 180000
#ifdef USE_ASSERT_CHECKING
	jstate->total_jumble_len += orig_size;
#endif
#endif
}

/*
 * AppendJumble
 *		Add 'size' bytes of the given jumble 'value' to the jumble state
 */
static pg_noinline void
AppendJumble(JumbleState *jstate, const unsigned char *value, Size size)
{
#if PG_VERSION_NUM >= 180000
	if (jstate->pending_nulls > 0)
		FlushPendingNulls(jstate);
#endif

	AppendJumbleVarlen(jstate, value, size);
}

#if PG_VERSION_NUM >= 180000
/*
 * AppendJumbleNull
 *		For jumbling NULL pointers
 */
static pg_attribute_always_inline void
AppendJumbleNull(JumbleState *jstate)
{
	jstate->pending_nulls++;
}
#endif

/*
 * AppendJumbleFixed
 *		Accumulate a small fixed-size value (1-8 bytes) directly into the
 *		fasthash state.
 */
static pg_attribute_always_inline void
AppendJumbleFixed(JumbleState *jstate, const unsigned char *value, Size size)
{
	fasthash_state *hs = JUMBLE_HASH_STATE(jstate);

#if PG_VERSION_NUM >= 180000
	if (jstate->pending_nulls > 0)
		FlushPendingNulls(jstate);
#endif

	fasthash_accum(hs, (const char *) value, size);
	jstate->jumble_len += size;

#if PG_VERSION_NUM >= 180000
#ifdef USE_ASSERT_CHECKING
	jstate->total_jumble_len += size;
#endif
#endif
}

/*
 * AppendJumble8
 *		Add the first byte from the given 'value' pointer to the jumble state
 */
static pg_noinline void
AppendJumble8(JumbleState *jstate, const unsigned char *value)
{
	AppendJumbleFixed(jstate, value, 1);
}

/*
 * AppendJumble16
 *		Add the first 2 bytes from the given 'value' pointer to the jumble
 *		state.
 */
static pg_noinline void
AppendJumble16(JumbleState *jstate, const unsigned char *value)
{
	AppendJumbleFixed(jstate, value, 2);
}

/*
 * AppendJumble32
 *		Add the first 4 bytes from the given 'value' pointer to the jumble
 *		state.
 */
static pg_noinline void
AppendJumble32(JumbleState *jstate, const unsigned char *value)
{
	AppendJumbleFixed(jstate, value, 4);
}

/*
 * AppendJumble64
 *		Add the first 8 bytes from the given 'value' pointer to the jumble
 *		state.
 */
static pg_noinline void
AppendJumble64(JumbleState *jstate, const unsigned char *value)
{
	AppendJumbleFixed(jstate, value, 8);
}

#if PG_VERSION_NUM >= 180000
/*
 * FlushPendingNulls
 *		Incorporate the pending_nulls value into the fasthash state.
 *
 * Note: Callers must ensure that there's at least 1 pending NULL.
 */
static pg_attribute_always_inline void
FlushPendingNulls(JumbleState *jstate)
{
	fasthash_state *hs = JUMBLE_HASH_STATE(jstate);

	Assert(jstate->pending_nulls > 0);

	fasthash_accum(hs, (const char *) &jstate->pending_nulls, 4);
	jstate->jumble_len += 4;
	jstate->pending_nulls = 0;
}
#endif


#if PG_VERSION_NUM >= 180000
/*
 * Subroutine for _jumbleElements: Verify a few simple cases where we can
 * deduce that the expression is a constant:
 *
 * - See through any wrapping RelabelType and CoerceViaIO layers.
 * - If it's a FuncExpr, check that the function is a builtin
 *   cast and its arguments are Const.
 * - Otherwise test if the expression is a simple Const or a
 *   PARAM_EXTERN param.
 */
static bool
IsSquashableConstant(Node *element)
{
restart:
	switch (nodeTag(element))
	{
		case T_RelabelType:
			/* Unwrap RelabelType */
			element = (Node *) ((RelabelType *) element)->arg;
			goto restart;

		case T_CoerceViaIO:
			/* Unwrap CoerceViaIO */
			element = (Node *) ((CoerceViaIO *) element)->arg;
			goto restart;

		case T_Const:
			return true;

		case T_Param:
			return castNode(Param, element)->paramkind == PARAM_EXTERN;

		case T_FuncExpr:
			{
				FuncExpr   *func = (FuncExpr *) element;
				ListCell   *temp;

				if (func->funcformat != COERCE_IMPLICIT_CAST &&
					func->funcformat != COERCE_EXPLICIT_CAST)
					return false;

				if (func->funcid > FirstGenbkiObjectId)
					return false;

				/*
				 * We can check function arguments recursively, being careful
				 * about recursing too deep.  At each recursion level it's
				 * enough to test the stack on the first element.  (Note that
				 * I wasn't able to hit this without bloating the stack
				 * artificially in this function: the parser errors out before
				 * stack size becomes a problem here.)
				 */
				foreach(temp, func->args)
				{
					Node	   *arg = lfirst(temp);

					if (!IsA(arg, Const))
					{
						if (foreach_current_index(temp) == 0 &&
							stack_is_too_deep())
							return false;
						else if (!IsSquashableConstant(arg))
							return false;
					}
				}

				return true;
			}

		default:
			return false;
	}
}

/*
 * Subroutine for _jumbleElements: Verify whether the provided list
 * can be squashed, meaning it contains only constant expressions.
 *
 * Return value indicates if squashing is possible.
 *
 * Note that this function searches only for explicit Const nodes with
 * possibly very simple decorations on top and PARAM_EXTERN parameters,
 * and does not try to simplify expressions.
 */
static bool
IsSquashableConstantList(List *elements)
{
	ListCell   *temp;

	/* If the list is too short, we don't try to squash it. */
	if (list_length(elements) < 2)
		return false;

	foreach(temp, elements)
	{
		if (!IsSquashableConstant(lfirst(temp)))
			return false;
	}

	return true;
}
#endif

#define JUMBLE_NODE(item) \
	JumbleNode(jstate, (Node *) expr->item)
#if PG_VERSION_NUM >= 180000
#define JUMBLE_ELEMENTS(list, node) \
	_jumbleElements(jstate, (List *) expr->list, node)
#endif
#define JUMBLE_LOCATION(location) // Intentionally not recording location
#define JUMBLE_FIELD(item) \
do { \
	if (sizeof(expr->item) == 8) \
		AppendJumble64(jstate, (const unsigned char *) &(expr->item)); \
	else if (sizeof(expr->item) == 4) \
		AppendJumble32(jstate, (const unsigned char *) &(expr->item)); \
	else if (sizeof(expr->item) == 2) \
		AppendJumble16(jstate, (const unsigned char *) &(expr->item)); \
	else if (sizeof(expr->item) == 1) \
		AppendJumble8(jstate, (const unsigned char *) &(expr->item)); \
	else \
		AppendJumble(jstate, (const unsigned char *) &(expr->item), sizeof(expr->item)); \
} while (0)
#if PG_VERSION_NUM >= 180000
#define JUMBLE_STRING(str) \
do { \
	if (expr->str) \
		AppendJumble(jstate, (const unsigned char *) (expr->str), strlen(expr->str) + 1); \
	else \
		AppendJumbleNull(jstate); \
} while(0)
#else
#define JUMBLE_STRING(str) \
do { \
	if (expr->str) \
		AppendJumble(jstate, (const unsigned char *) (expr->str), strlen(expr->str) + 1); \
} while(0)
#endif
/* Function name used for the node field attribute custom_query_jumble. */
#define JUMBLE_CUSTOM(nodetype, item) \
	_jumble##nodetype##_##item(jstate, expr, expr->item)

#define JUMBLE_BITMAPSET(item) \
do { \
	if (expr->item && expr->item->nwords > 0) \
		AppendJumble(jstate, (const unsigned char *) expr->item->words, sizeof(bitmapword) * expr->item->nwords); \
} while(0)
#define JUMBLE_ARRAY(item, len) \
do { \
	if (len > 0) \
		AppendJumble(jstate, (const unsigned char *) expr->item, sizeof(*(expr->item)) * len); \
} while(0)

#if PG_VERSION_NUM >= 190000
#include "pg19_jumblefuncs.funcs.c"
#elif PG_VERSION_NUM >= 180000
#include "pg18_jumblefuncs.funcs.c"
#elif PG_VERSION_NUM >= 170000
#include "pg17_jumblefuncs.funcs.c"
#elif PG_VERSION_NUM >= 160000
#include "pg16_jumblefuncs.funcs.c"
#else
#error "Unsupported Postgres version - Postgres 16 or newer required"
#endif

#if PG_VERSION_NUM >= 180000
/*
 * We try to jumble lists of expressions as one individual item regardless
 * of how many elements are in the list. This is know as squashing, which
 * results in different queries jumbling to the same query_id, if the only
 * difference is the number of elements in the list.
 *
 * We allow constants and PARAM_EXTERN parameters to be squashed. To normalize
 * such queries, we use the start and end locations of the list of elements in
 * a list.
 */
static void
_jumbleElements(JumbleState *jstate, List *elements, Node *node)
{
	bool		normalize_list = false;

	if (IsSquashableConstantList(elements))
	{
		if (IsA(node, ArrayExpr))
		{
			ArrayExpr  *aexpr = (ArrayExpr *) node;

			if (aexpr->list_start > 0 && aexpr->list_end > 0)
			{
				normalize_list = true;
				jstate->has_squashed_lists = true;
			}
		}
	}

	if (!normalize_list)
	{
		JumbleNode(jstate, (Node *) elements);
	}
}

static void
_jumbleParam(JumbleState *jstate, Node *node)
{
	Param	   *expr = (Param *) node;

	JUMBLE_FIELD(paramkind);
	JUMBLE_FIELD(paramid);
	JUMBLE_FIELD(paramtype);
	/* paramtypmod and paramcollid are ignored */
}
#endif

void
JumbleNode(JumbleState *jstate, Node *node)
{
	Node	   *expr = node;
#if PG_VERSION_NUM >= 180000
#ifdef USE_ASSERT_CHECKING
	Size		prev_jumble_len = jstate->total_jumble_len;
#endif
#endif

	if (expr == NULL)
	{
#if PG_VERSION_NUM >= 180000
		AppendJumbleNull(jstate);
#endif
		return;
	}

	/* Guard against stack overflow due to overly complex expressions */
	check_stack_depth();

	/*
	 * We always emit the node's NodeTag, then any additional fields that are
	 * considered significant, and then we recurse to any child nodes.
	 */
	JUMBLE_FIELD(type);

	switch (nodeTag(expr))
	{
#if PG_VERSION_NUM >= 190000
#include "pg19_jumblefuncs.switch.c"
#elif PG_VERSION_NUM >= 180000
#include "pg18_jumblefuncs.switch.c"
#elif PG_VERSION_NUM >= 170000
#include "pg17_jumblefuncs.switch.c"
#elif PG_VERSION_NUM >= 160000
#include "pg16_jumblefuncs.switch.c"
#else
#error "Unsupported Postgres version - Postgres 16 or newer required"
#endif

		case T_List:
		case T_IntList:
		case T_OidList:
		case T_XidList:
			_jumbleList(jstate, expr);
			break;

		default:
			/* Only a warning, since we can stumble along anyway */
			elog(WARNING, "unrecognized node type: %d",
				 (int) nodeTag(expr));
			break;
	}

#if PG_VERSION_NUM >= 180000
	/* Ensure we added something to the jumble buffer */
	Assert(jstate->total_jumble_len > prev_jumble_len);
#endif
}

static void
_jumbleList(JumbleState *jstate, Node *node)
{
	List	   *expr = (List *) node;
	ListCell   *l;

	switch (expr->type)
	{
		case T_List:
			foreach(l, expr)
				JumbleNode(jstate, lfirst(l));
			break;
		case T_IntList:
			foreach(l, expr)
				AppendJumble32(jstate, (const unsigned char *) &lfirst_int(l));
			break;
		case T_OidList:
			foreach(l, expr)
				AppendJumble32(jstate, (const unsigned char *) &lfirst_oid(l));
			break;
		case T_XidList:
			foreach(l, expr)
				AppendJumble32(jstate, (const unsigned char *) &lfirst_xid(l));
			break;
		default:
			elog(ERROR, "unrecognized list node type: %d",
				 (int) expr->type);
			return;
	}
}

static void
_jumbleA_Const(JumbleState *jstate, Node *node)
{
	A_Const    *expr = (A_Const *) node;

	JUMBLE_FIELD(isnull);
	if (!expr->isnull)
	{
		JUMBLE_FIELD(val.node.type);
		switch (nodeTag(&expr->val))
		{
			case T_Integer:
				JUMBLE_FIELD(val.ival.ival);
				break;
			case T_Float:
				JUMBLE_STRING(val.fval.fval);
				break;
			case T_Boolean:
				JUMBLE_FIELD(val.boolval.boolval);
				break;
			case T_String:
				JUMBLE_STRING(val.sval.sval);
				break;
			case T_BitString:
				JUMBLE_STRING(val.bsval.bsval);
				break;
			default:
				elog(ERROR, "unrecognized node type: %d",
					 (int) nodeTag(&expr->val));
				break;
		}
	}
}

#if PG_VERSION_NUM < 170000
static void
_jumbleRangeTblEntry(JumbleState *jstate, Node *node)
{
	RangeTblEntry *expr = (RangeTblEntry *) node;

	JUMBLE_FIELD(rtekind);
	switch (expr->rtekind)
	{
		case RTE_RELATION:
			JUMBLE_FIELD(relid);
			JUMBLE_NODE(tablesample);
			JUMBLE_FIELD(inh);
			break;
		case RTE_SUBQUERY:
			JUMBLE_NODE(subquery);
			break;
		case RTE_JOIN:
			JUMBLE_FIELD(jointype);
			break;
		case RTE_FUNCTION:
			JUMBLE_NODE(functions);
			break;
		case RTE_TABLEFUNC:
			JUMBLE_NODE(tablefunc);
			break;
		case RTE_VALUES:
			JUMBLE_NODE(values_lists);
			break;
		case RTE_CTE:

			/*
			 * Depending on the CTE name here isn't ideal, but it's the only
			 * info we have to identify the referenced WITH item.
			 */
			JUMBLE_STRING(ctename);
			JUMBLE_FIELD(ctelevelsup);
			break;
		case RTE_NAMEDTUPLESTORE:
			JUMBLE_STRING(enrname);
			break;
		case RTE_RESULT:
			break;
		default:
			elog(ERROR, "unrecognized RTE kind: %d", (int) expr->rtekind);
			break;
	}
}
#elif PG_VERSION_NUM >= 180000
/*
 * Custom query jumble function for RangeTblEntry.eref.
 */
static void
_jumbleRangeTblEntry_eref(JumbleState *jstate,
						  RangeTblEntry *rte,
						  Alias *expr)
{
	JUMBLE_FIELD(type);

	/*
	 * This includes only the table name, the list of column names is ignored.
	 */
	JUMBLE_STRING(aliasname);
}
#endif

#if PG_VERSION_NUM >= 180000
static void
_jumbleVariableSetStmt(JumbleState *jstate, Node *node)
{
	VariableSetStmt *expr = (VariableSetStmt *) node;

	JUMBLE_FIELD(kind);
	JUMBLE_STRING(name);

	/*
	 * Account for the list of arguments in query jumbling only if told by the
	 * parser.
	 */
	if (expr->jumble_args)
		JUMBLE_NODE(args);
	JUMBLE_FIELD(is_local);
	JUMBLE_LOCATION(location);
}
#endif

/*
 * Jumble the entries in the rangle table to map RT indexes to relations
 *
 * This ensures jumbled RT indexes (e.g. in a Scan or Modify node), are
 * distinguished by the target of the RT entry, even if the index is the same.
 */
void
JumbleRangeTable(JumbleState *jstate, List *rtable)
{
	ListCell   *lc;

	foreach(lc, rtable)
	{
		RangeTblEntry *expr = lfirst_node(RangeTblEntry, lc);

		switch (expr->rtekind)
		{
			case RTE_RELATION:
				JUMBLE_FIELD(relid);
				break;
			case RTE_CTE:
				JUMBLE_STRING(ctename);
				break;
			default:

				/*
				 * Ignore other targets, the jumble includes something
				 * identifying about them already
				 */
				break;
		}
	}
}
