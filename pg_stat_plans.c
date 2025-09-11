/*--------------------------------------------------------------------------
 *
 * pg_stat_plans.c
 *		Track per-plan call counts, execution times and EXPLAIN texts
 *		across a whole database cluster.
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		contrib/pg_stat_plans/pg_stat_plans.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/parallel.h"
#include "catalog/pg_authid.h"
#include "commands/explain.h"
#if PG_VERSION_NUM >= 180000
#include "commands/explain_format.h"
#include "commands/explain_state.h"
#endif
#include "common/hashfn.h"
#include "funcapi.h"
#include "lib/dshash.h"
#include "libpq/auth.h"
#include "mb/pg_wchar.h"
#include "nodes/queryjumble.h"
#include "optimizer/planner.h"
#include "parser/analyze.h"
#include "pgstat.h"
#include "storage/ipc.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/snapmgr.h"

#include "jumblefuncs.h"
#include "pgstat_custom.h"

#ifdef USE_ZSTD
#include <zstd.h>
#endif

PG_MODULE_MAGIC;

/* Current nesting depth of planner/ExecutorRun/ProcessUtility calls */
static int	nesting_level = 0;

/* Saved hook values */
static post_parse_analyze_hook_type prev_post_parse_analyze_hook = NULL;
static planner_hook_type prev_planner_hook = NULL;
static ExecutorStart_hook_type prev_ExecutorStart = NULL;
static ExecutorRun_hook_type prev_ExecutorRun = NULL;
static ExecutorFinish_hook_type prev_ExecutorFinish = NULL;
static ExecutorEnd_hook_type prev_ExecutorEnd = NULL;
static ProcessUtility_hook_type prev_ProcessUtility = NULL;

/*---- GUC variables ----*/

typedef enum
{
	PGSP_TRACK_NONE,			/* track no plans */
	PGSP_TRACK_TOP,				/* only plans for top level statements */
	PGSP_TRACK_ALL,				/* all plans, including for nested statements */
}			PGSPTrackLevel;

static const struct config_enum_entry track_options[] =
{
	{"none", PGSP_TRACK_NONE, false},
	{"top", PGSP_TRACK_TOP, false},
	{"all", PGSP_TRACK_ALL, false},
	{NULL, 0, false}
};

typedef enum
{
	PGSP_COMPRESS_NONE,			/* no compression */
	PGSP_COMPRESS_ZSTD,			/* zstd compression */
}			PGSPCompression;

static const struct config_enum_entry compress_options[] =
{
	{"none", PGSP_COMPRESS_NONE, false},
	{"zstd", PGSP_COMPRESS_ZSTD, false},
	{NULL, 0, false}
};

static int	pgsp_max = 5000;	/* max # plans to track */
static int	pgsp_max_size = 2048;	/* max size of plan text to track (in
									 * bytes) */
static int	pgsp_track = PGSP_TRACK_TOP;	/* tracking level */
static int	pgsp_compress = PGSP_COMPRESS_NONE; /* compression type */

#define pgsp_enabled(level) \
	(!IsParallelWorker() && \
	(pgsp_track == PGSP_TRACK_ALL || \
	(pgsp_track == PGSP_TRACK_TOP && (level) == 0)))

#define USAGE_INCREASE			0.5 /* increase by this each time we report
									 * stats */
#define USAGE_DECREASE_FACTOR	(0.99)	/* decreased every
										 * pgstat_dealloc_plans */
#define USAGE_DEALLOC_PERCENT	5	/* free this % of entries at once */

/*---- Function declarations ----*/

PG_FUNCTION_INFO_V1(pg_stat_plans_reset);
PG_FUNCTION_INFO_V1(pg_stat_plans_2_0);
PG_FUNCTION_INFO_V1(pg_stat_plans_2_0_get_activity);

/* Structures for statistics of plans */
typedef struct PgStatShared_PlanInfo
{
	/* key elements that identify a plan (together with the dboid) */
	uint64		planid;
	uint64		queryid;
	Oid			userid;			/* userid is tracked to allow users to see
								 * their own query plans */
	bool		toplevel;		/* query executed at top level */

	dsa_pointer plan_text;		/* pointer to DSA memory containing plan text */
	size_t		plan_text_size; /* size of stored plan text */
	bool		plan_text_truncated;	/* whether stored plan text was
										 * truncated due to text size limit */
	int			plan_text_compression;	/* plan compression used */
	int			plan_encoding;	/* plan text encoding */
}			PgStatShared_PlanInfo;

typedef struct PgStat_StatPlanEntry
{
	PgStat_Counter exec_count;
	double		exec_time;
	double		usage;			/* Usage factor of the entry, used to
								 * prioritize which plans to age out */

	/* Only used in shared structure, not in local pending stats */
	PgStatShared_PlanInfo info;
}			PgStat_StatPlanEntry;

typedef struct PgStatShared_Plan
{
	PgStatShared_Common header;
	PgStat_StatPlanEntry stats;
}			PgStatShared_Plan;

static bool plan_stats_flush_cb(PgStat_EntryRef *entry_ref, bool nowait);
static uint64 pgsp_calculate_plan_id(PlannedStmt *result);

static const PgStat_KindInfo plan_stats = {
	.name = "plan_stats",
	.fixed_amount = false,

#if PG_VERSION_NUM >= 180000
	/*
	 * We currently don't write to a file since plan texts would get lost (and
	 * just the stats on their own aren't that useful)
	 */
	.write_to_file = false,
#endif

	/*
	 * Plan statistics are available system-wide to simplify monitoring
	 * scripts
	 */
	.accessed_across_databases = true,

	.shared_size = sizeof(PgStatShared_Plan),
	.shared_data_off = offsetof(PgStatShared_Plan, stats),
	.shared_data_len = sizeof(((PgStatShared_Plan *) 0)->stats),
	.pending_size = sizeof(PgStat_StatPlanEntry),
	.flush_pending_cb = plan_stats_flush_cb,
};

/*
 * Compute stats entry idx from query ID and plan ID with an 8-byte hash.
 *
 * Whilst we could theorically just use the plan ID here, we intentionally
 * add the query ID into the mix to ease interpreting the data in combination
 * with pg_stat_statements.
 */
#define PGSTAT_PLAN_IDX(query_id, plan_id, user_id, toplevel) hash_combine64(toplevel, hash_combine64(query_id, hash_combine64(plan_id, user_id)))

/*
 * Kind ID reserved for statistics of plans.
 */
#if PG_VERSION_NUM >= 180000
#define PGSTAT_KIND_PLANS	PGSTAT_KIND_EXPERIMENTAL	/* TODO: Assign */
#else
#define PGSTAT_KIND_PLANS	24	/* TODO: Assign */
#endif

/*
 * Callback for stats handling
 */
static bool
plan_stats_flush_cb(PgStat_EntryRef *entry_ref, bool nowait)
{
	PgStat_StatPlanEntry *localent;
	PgStatShared_Plan *shfuncent;

	localent = (PgStat_StatPlanEntry *) entry_ref->pending;
	shfuncent = (PgStatShared_Plan *) entry_ref->shared_stats;

	if (!pgstat_custom_lock_entry(entry_ref, nowait))
		return false;

	shfuncent->stats.exec_count += localent->exec_count;
	shfuncent->stats.exec_time += localent->exec_time;
	shfuncent->stats.usage += localent->usage;

	pgstat_custom_unlock_entry(entry_ref);

	return true;
}

static char *
pgsp_explain_plan(QueryDesc *queryDesc)
{
	ExplainState *es;
	StringInfo	es_str;

	es = NewExplainState();
	es_str = es->str;

	/*
	 * We turn off COSTS since identical planids may have very different
	 * costs, and it could be misleading to only show the first recorded
	 * plan's costs.
	 */
	es->costs = false;
	es->format = EXPLAIN_FORMAT_TEXT;

	ExplainBeginOutput(es);
	ExplainPrintPlan(es, queryDesc);
	ExplainEndOutput(es);

	/* Ignore trailing newline emitted by ExplainPrintPlan */
	if (es_str->len > 0)
		es_str->data[es_str->len - 1] = '\0';

	return es_str->data;
}

static void
pgstat_gc_plan_memory()
{
	dshash_seq_status hstat;
	PgStatShared_HashEntry *p;

	/* dshash entry is not modified, take shared lock */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, false);
	while ((p = dshash_seq_next(&hstat)) != NULL)
	{
		PgStatShared_Common *header;
		PgStat_StatPlanEntry *statent;

		if (!p->dropped || p->key.kind != PGSTAT_KIND_PLANS)
			continue;

		header = dsa_get_address(pgStatCustomLocal.dsa, p->body);

		if (!LWLockConditionalAcquire(&header->lock, LW_EXCLUSIVE))
			continue;

		statent = (PgStat_StatPlanEntry *) pgstat_custom_get_entry_data(PGSTAT_KIND_PLANS, header);

		/*
		 * Clean up this entry's plan text allocation, if we haven't done so
		 * already
		 */
		if (DsaPointerIsValid(statent->info.plan_text))
		{
			dsa_free(pgStatCustomLocal.dsa, statent->info.plan_text);
			statent->info.plan_text = InvalidDsaPointer;

			/* Allow removal of the shared stats entry */
			pg_atomic_fetch_sub_u32(&p->refcount, 1);
		}

		LWLockRelease(&header->lock);
	}
	dshash_seq_term(&hstat);

	/* Encourage other backends to clean up dropped entry refs */
	pgstat_custom_request_entry_refs_gc();
}

typedef struct PlanDeallocEntry
{
	PgStat_HashKey key;
	double		usage;
}			PlanDeallocEntry;

/*
 * list sort comparator for sorting into decreasing usage order
 */
static int
entry_cmp_lru(const union ListCell *lhs, const union ListCell *rhs)
{
	double		l_usage = ((PlanDeallocEntry *) lfirst(lhs))->usage;
	double		r_usage = ((PlanDeallocEntry *) lfirst(rhs))->usage;

	if (l_usage > r_usage)
		return -1;
	else if (l_usage < r_usage)
		return +1;
	else
		return 0;
}

static void
pgstat_dealloc_plans()
{
	dshash_seq_status hstat;
	PgStatShared_HashEntry *p;
	List	   *entries = NIL;
	ListCell   *lc;
	int			nvictims;

	/* dshash entry is not modified, take shared lock */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, false);
	while ((p = dshash_seq_next(&hstat)) != NULL)
	{
		PgStatShared_Common *header;
		PgStat_StatPlanEntry *statent;
		PlanDeallocEntry *entry;

		if (p->dropped || p->key.kind != PGSTAT_KIND_PLANS)
			continue;

		header = dsa_get_address(pgStatCustomLocal.dsa, p->body);

		if (!LWLockConditionalAcquire(&header->lock, LW_EXCLUSIVE))
			continue;

		statent = (PgStat_StatPlanEntry *) pgstat_custom_get_entry_data(PGSTAT_KIND_PLANS, header);
		statent->usage *= USAGE_DECREASE_FACTOR;

		entry = palloc(sizeof(PlanDeallocEntry));
		entry->key = p->key;
		entry->usage = statent->usage;

		LWLockRelease(&header->lock);

		entries = lappend(entries, entry);
	}
	dshash_seq_term(&hstat);

	/* Sort by usage ascending (lowest used entries are last) */
	list_sort(entries, entry_cmp_lru);

	/* At a minimum, deallocate 10 entries to make it worth our while */
	nvictims = Max(10, list_length(entries) * USAGE_DEALLOC_PERCENT / 100);
	nvictims = Min(nvictims, list_length(entries));

	/* Actually drop the entries */
	for_each_from(lc, entries, list_length(entries) - nvictims)
	{
		PlanDeallocEntry *entry = lfirst(lc);

#if PG_VERSION_NUM >= 180000
		pgstat_custom_drop_entry(entry->key.kind, entry->key.dboid, entry->key.objid);
#else
		pgstat_custom_drop_entry(entry->key.kind, entry->key.dboid, entry->key.objoid);
#endif
	}

	/* Clean up our working memory immediately */
	foreach(lc, entries)
	{
		PlanDeallocEntry *entry = lfirst(lc);

		pfree(entry);
	}
	pfree(entries);
}

static void
pgstat_gc_plans()
{
	dshash_seq_status hstat;
	PgStatShared_HashEntry *p;
	bool		have_dropped_entries = false;
	size_t		plan_entry_count = 0;

	/* TODO: Prevent concurrent GC cycles - flag an active GC run somehow */

	/*
	 * Count our active entries, and whether there are any dropped entries we
	 * may need to clean up at the end.
	 */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, false);
	while ((p = dshash_seq_next(&hstat)) != NULL)
	{
		if (p->key.kind != PGSTAT_KIND_PLANS)
			continue;

		if (p->dropped)
			have_dropped_entries = true;
		else
			plan_entry_count++;
	}
	dshash_seq_term(&hstat);

	/*
	 * If we're over the limit, delete entries with lowest usage factor.
	 */
	if (plan_entry_count > pgsp_max)
	{
		pgstat_dealloc_plans();
		have_dropped_entries = true;	/* Assume we did some work */
	}

	/* If there are dropped entries, clean up their plan memory if needed */
	if (have_dropped_entries)
		pgstat_gc_plan_memory();
}

static char *
pgsp_compress_plan_text_zstd(char *plan, size_t plan_len, size_t *stored_plan_size, bool *stored_plan_truncated)
{
#ifdef USE_ZSTD
	ZSTD_CCtx  *cctx = ZSTD_createCCtx();
	ZSTD_outBuffer outBuf = {0};
	int			level = ZSTD_CLEVEL_DEFAULT;
	size_t		compressStep = 100; /* Compress in 100 byte input increments */
	size_t		yet_to_flush;

	size_t		ret = ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel,
											 level);

	if (ZSTD_isError(ret))
	{
		elog(INFO, "could not set zstd compression level to %d: %s",
			 level, ZSTD_getErrorName(ret));
		return NULL;
	}

	/* Allocate the output buffer to its largest allowed extent, since we */
	/* re-allocate anyway when copying into DSA */
	outBuf.dst = palloc0(sizeof(char) * pgsp_max_size);
	outBuf.size = pgsp_max_size;
	outBuf.pos = 0;

	/*
	 * Compress data in steps, stopping early if we're likely to exceed our
	 * limit
	 */
	for (int pos = 0; pos < plan_len; pos += compressStep)
	{
		ZSTD_inBuffer inBuf = {plan + pos, Min(compressStep, plan_len - pos), 0};

		do
		{
			size_t		max_needed = ZSTD_compressBound(inBuf.size - inBuf.pos);

			if (outBuf.size - outBuf.pos < max_needed)
			{
				elog(INFO, "FIXME: unexpected short bound");
				return NULL;
			}

			yet_to_flush = ZSTD_compressStream2(cctx,
												&outBuf,
												&inBuf, ZSTD_e_continue);

			if (ZSTD_isError(yet_to_flush))
			{
				elog(INFO, "could not compress data: %s",
					 ZSTD_getErrorName(yet_to_flush));
				return NULL;
			}
		} while (yet_to_flush > 0);

		/*
		 * Stop early if output pos is close to max (to leave room for closing
		 * current frame)
		 */
		if ((outBuf.pos + compressStep) > outBuf.size * 0.95)
		{
			*stored_plan_truncated = true;
			break;
		}
	}

	/* Close current frame */
	do
	{
		ZSTD_inBuffer inBuf = {NULL, 0, 0};
		size_t		max_needed = ZSTD_compressBound(0);

		if (outBuf.size - outBuf.pos < max_needed)
		{
			elog(INFO, "FIXME: repalloc?");
			return NULL;
		}

		yet_to_flush = ZSTD_compressStream2(cctx,
											&outBuf,
											&inBuf, ZSTD_e_end);

		if (ZSTD_isError(yet_to_flush))
		{
			elog(INFO, "could not compress data: %s",
				 ZSTD_getErrorName(yet_to_flush));
			return NULL;
		}
	} while (yet_to_flush > 0);

	*stored_plan_size = outBuf.pos;

	return outBuf.dst;
#else
	elog(INFO, "zstd compression not enabled in build, falling back to no compression");
	return NULL;
#endif
}

static char *
pgsp_decompress_plan_text_zstd(char *stored_plan, size_t stored_plan_size)
{
#ifdef USE_ZSTD
	ZSTD_DCtx  *const dctx = ZSTD_createDCtx();
	ZSTD_inBuffer inBuf = {stored_plan, stored_plan_size, 0};
	ZSTD_outBuffer outBuf = {0};
	size_t		ret;

	outBuf.dst = palloc(sizeof(char) * pgsp_max_size * 20); /* TODO: Don't hardcode
															 * this */
	outBuf.size = pgsp_max_size * 20;

	ret = ZSTD_decompressStream(dctx, &outBuf, &inBuf);
	if (ZSTD_isError(ret))
		elog(ERROR, "could not decompress data: %s",
			 ZSTD_getErrorName(ret));
	if (ret != 0)
		elog(ERROR, "EOF before end of stream: %zu", ret);

	ZSTD_freeDCtx(dctx);

	((char *) outBuf.dst)[outBuf.pos] = '\0';

	return outBuf.dst;
#else
	elog(ERROR, "zstd compression not enabled in build (BUG: how did we get a plan that was marked as such?)");
	return NULL;
#endif
}

static char *
pgsp_compress_plan_text(char *plan, size_t *stored_plan_size, bool *stored_plan_truncated, int *stored_plan_compression)
{
	size_t		plan_len = strlen(plan);

	if (pgsp_compress == PGSP_COMPRESS_ZSTD)
	{
		char	   *stored_plan = pgsp_compress_plan_text_zstd(plan, plan_len, stored_plan_size, stored_plan_truncated);

		if (stored_plan != NULL)
		{
			*stored_plan_compression = PGSP_COMPRESS_ZSTD;
			return stored_plan;
		}
	}

	/* Default (no compression) */
	*stored_plan_size = Min(plan_len, pgsp_max_size);
	*stored_plan_truncated = plan_len > pgsp_max_size;
	*stored_plan_compression = PGSP_COMPRESS_NONE;

	return plan;
}

static char *
pgsp_decompress_plan_text(char *stored_plan, size_t stored_plan_size, int stored_plan_compression)
{
	switch (stored_plan_compression)
	{
		case PGSP_COMPRESS_ZSTD:
			{
				return pgsp_decompress_plan_text_zstd(stored_plan, stored_plan_size);
			}
		case PGSP_COMPRESS_NONE:
			{
				char	   *plan = palloc(sizeof(char) * stored_plan_size + 1);

				memcpy(plan, stored_plan, stored_plan_size);
				plan[stored_plan_size] = '\0';
				return plan;
			}
	}

	pg_unreachable();
}

static void
pgstat_report_plan_stats(QueryDesc *queryDesc,
						 PgStat_Counter exec_count,
						 double exec_time)
{
	PgStat_EntryRef *entry_ref;
	PgStatShared_Plan *shstatent;
	PgStat_StatPlanEntry *statent;
	bool		newly_created;
	uint64		queryId = queryDesc->plannedstmt->queryId;
	uint64		planId;
	Oid			userid = GetUserId();
	bool		toplevel = (nesting_level == 0);

#if PG_VERSION_NUM >= 180000
	planId = queryDesc->plannedstmt->planId;
#else
	planId = pgsp_calculate_plan_id(queryDesc->plannedstmt);
#endif

	entry_ref = pgstat_custom_prep_pending_entry(PGSTAT_KIND_PLANS, MyDatabaseId,
										  PGSTAT_PLAN_IDX(queryId, planId, userid, toplevel), &newly_created);

	shstatent = (PgStatShared_Plan *) entry_ref->shared_stats;
	statent = &shstatent->stats;

	if (newly_created)
	{
		char	   *plan = pgsp_explain_plan(queryDesc);
		size_t		stored_plan_size = 0;
		bool		stored_plan_truncated = false;
		int			stored_plan_compression = 0;
		char	   *stored_plan = pgsp_compress_plan_text(plan, &stored_plan_size, &stored_plan_truncated, &stored_plan_compression);

		(void) pgstat_custom_lock_entry(entry_ref, false);

		/*
		 * We may be over the limit, so run GC now before saving entry (we do
		 * this whilst holding the lock on the new entry so we don't remove it
		 * by accident)
		 */
		pgstat_gc_plans();

		shstatent->stats.info.planid = planId;
		shstatent->stats.info.queryid = queryId;
		shstatent->stats.info.userid = userid;
		shstatent->stats.info.toplevel = toplevel;
		shstatent->stats.info.plan_text = dsa_allocate(pgStatCustomLocal.dsa, stored_plan_size);
		memcpy(dsa_get_address(pgStatCustomLocal.dsa, shstatent->stats.info.plan_text), stored_plan, stored_plan_size);
		shstatent->stats.info.plan_text_size = stored_plan_size;
		shstatent->stats.info.plan_text_truncated = stored_plan_truncated;
		shstatent->stats.info.plan_text_compression = stored_plan_compression;
		shstatent->stats.info.plan_encoding = GetDatabaseEncoding();

		/*
		 * Increase refcount here so entry can't get released without us
		 * dropping the plan text
		 */
		pg_atomic_fetch_add_u32(&entry_ref->shared_entry->refcount, 1);

		pgstat_custom_unlock_entry(entry_ref);

		pfree(plan);
	}

	statent->exec_count += exec_count;
	statent->exec_time += exec_time;
	statent->usage += USAGE_INCREASE;
}

static void
pgsp_plan_id_walker(JumbleState *jstate, Plan *plan)
{
	ListCell   *l;

	if (plan == NULL)
		return;

	/*
	 * Plan-type-specific walks
	 */
	switch (nodeTag(plan))
	{
		case T_SubqueryScan:
			{
				SubqueryScan *sscan = (SubqueryScan *) plan;

				pgsp_plan_id_walker(jstate, sscan->subplan);
			}
			break;
		case T_CustomScan:
			{
				CustomScan *cscan = (CustomScan *) plan;

				foreach(l, cscan->custom_plans)
				{
					pgsp_plan_id_walker(jstate, (Plan *) lfirst(l));
				}
			}
			break;
		case T_Append:
			{
				Append	   *aplan = (Append *) plan;

				foreach(l, aplan->appendplans)
				{
					pgsp_plan_id_walker(jstate, (Plan *) lfirst(l));
				}
			}
			break;
		case T_MergeAppend:
			{
				MergeAppend *mplan = (MergeAppend *) plan;

				foreach(l, mplan->mergeplans)
				{
					pgsp_plan_id_walker(jstate, (Plan *) lfirst(l));
				}
			}
			break;
		case T_BitmapAnd:
			{
				BitmapAnd  *splan = (BitmapAnd *) plan;

				foreach(l, splan->bitmapplans)
				{
					pgsp_plan_id_walker(jstate, (Plan *) lfirst(l));
				}
			}
			break;
		case T_BitmapOr:
			{
				BitmapOr   *splan = (BitmapOr *) plan;

				foreach(l, splan->bitmapplans)
				{
					pgsp_plan_id_walker(jstate, (Plan *) lfirst(l));
				}
			}
			break;
		default:
			{
				/* do nothing */
			}
	}

	pgsp_plan_id_walker(jstate, plan->lefttree);
	pgsp_plan_id_walker(jstate, plan->righttree);

	JumbleNode(jstate, (Node *) plan);
}

static uint64
pgsp_calculate_plan_id(PlannedStmt *result)
{
	JumbleState *jstate = InitJumble();
	ListCell   *lc;
	uint64 planId;

	pgsp_plan_id_walker(jstate, result->planTree);
	foreach(lc, result->subplans)
	{
		Plan	   *subplan = (Plan *) lfirst(lc);

		pgsp_plan_id_walker(jstate, subplan);
	}

	JumbleRangeTable(jstate, result->rtable);
	planId = HashJumbleState(jstate);
	pfree(jstate);
	return planId;
}

/*
 * Planner hook: forward to regular planner, but increase plan count and
 * record query plan if needed.
 */
static PlannedStmt *
pgsp_planner(Query *parse,
			 const char *query_string,
			 int cursorOptions,
			 ParamListInfo boundParams)
{
	PlannedStmt *result;

	/*
	 * Increment the nesting level, to ensure that functions evaluated during
	 * planning are not seen as top-level calls.
	 */
	nesting_level++;
	PG_TRY();
	{
		if (prev_planner_hook)
			result = prev_planner_hook(parse, query_string, cursorOptions,
									   boundParams);
		else
			result = standard_planner(parse, query_string, cursorOptions,
									  boundParams);
	}
	PG_FINALLY();
	{
		nesting_level--;
	}
	PG_END_TRY();

#if PG_VERSION_NUM >= 180000
	if (pgsp_enabled(nesting_level))
		result->planId = pgsp_calculate_plan_id(result);
#endif

	return result;
}


/*
 * Post-parse-analysis hook: Reset query ID to support EXECUTE statements
 */
static void
pgsp_post_parse_analyze(ParseState *pstate, Query *query, JumbleState *jstate)
{
	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query, jstate);

	/* Safety check... */
	if (!pgsp_enabled(nesting_level))
		return;

	/*
	 * If it's EXECUTE, clear the queryId. This matches pg_stat_statements and
	 * is necessary to make pg_stat_plans_activity work correctly for EXECUTE
	 * statements when pg_stat_statements is not loaded.
	 */
	if (query->utilityStmt && IsA(query->utilityStmt, ExecuteStmt))
		query->queryId = UINT64CONST(0);
}

/*
 * ExecutorStart hook: start up tracking if needed
 */
static void
pgsp_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	uint64		queryId = queryDesc->plannedstmt->queryId;
#if PG_VERSION_NUM >= 180000
	uint64		planId = queryDesc->plannedstmt->planId;
#endif

	if (prev_ExecutorStart)
		prev_ExecutorStart(queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);

	if (queryId != UINT64CONST(0) &&
#if PG_VERSION_NUM >= 180000
		planId != UINT64CONST(0) &&
#endif
		pgsp_enabled(nesting_level))
	{
#if PG_VERSION_NUM >= 180000
		/*
		 * Record initial entry now, so plan text is available for currently
		 * running queries
		 */
		pgstat_report_plan_stats(queryDesc,
								 0, /* executions are counted in
									 * pgsp_ExecutorEnd */
								 0.0);
#endif

		/*
		 * Set up to track total elapsed time in ExecutorRun.  Make sure the
		 * space is allocated in the per-query context so it will go away at
		 * ExecutorEnd.
		 */
		if (queryDesc->totaltime == NULL)
		{
			MemoryContext oldcxt;

			oldcxt = MemoryContextSwitchTo(queryDesc->estate->es_query_cxt);
			queryDesc->totaltime = InstrAlloc(1, INSTRUMENT_ALL, false);
			MemoryContextSwitchTo(oldcxt);
		}
	}
}

/*
 * ExecutorRun hook: all we need do is track nesting depth
 */
static void
#if PG_VERSION_NUM >= 180000
pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count)
#else
pgsp_ExecutorRun(QueryDesc *queryDesc, ScanDirection direction, uint64 count, bool execute_once)
#endif
{
	nesting_level++;
	PG_TRY();
	{
#if PG_VERSION_NUM >= 180000
		if (prev_ExecutorRun)
			prev_ExecutorRun(queryDesc, direction, count);
		else
			standard_ExecutorRun(queryDesc, direction, count);
#else
		if (prev_ExecutorRun)
			prev_ExecutorRun(queryDesc, direction, count, execute_once);
		else
			standard_ExecutorRun(queryDesc, direction, count, execute_once);
#endif
	}
	PG_FINALLY();
	{
		nesting_level--;
	}
	PG_END_TRY();
}

/*
 * ExecutorFinish hook: all we need do is track nesting depth
 */
static void
pgsp_ExecutorFinish(QueryDesc *queryDesc)
{
	nesting_level++;
	PG_TRY();
	{
		if (prev_ExecutorFinish)
			prev_ExecutorFinish(queryDesc);
		else
			standard_ExecutorFinish(queryDesc);
	}
	PG_FINALLY();
	{
		nesting_level--;
	}
	PG_END_TRY();
}

/*
 * ExecutorEnd hook: store results if needed
 */
static void
pgsp_ExecutorEnd(QueryDesc *queryDesc)
{
	uint64		queryId = queryDesc->plannedstmt->queryId;
#if PG_VERSION_NUM >= 180000
	uint64		planId = queryDesc->plannedstmt->planId;
#endif

	if (queryId != UINT64CONST(0) &&
#if PG_VERSION_NUM >= 180000
		planId != UINT64CONST(0) &&
#endif
		queryDesc->totaltime && pgsp_enabled(nesting_level))
	{
		/*
		 * Make sure stats accumulation is done.  (Note: it's okay if several
		 * levels of hook all do this.)
		 */
		InstrEndLoop(queryDesc->totaltime);

		pgstat_report_plan_stats(queryDesc,
								 1,
								 queryDesc->totaltime->total * 1000.0 /* convert to msec */ );

#if PG_VERSION_NUM < 180000
		/* TODO: Is there a better way to do this on < PG18? */
		pgstat_custom_report_stat(true);
#endif
	}

	if (prev_ExecutorEnd)
		prev_ExecutorEnd(queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

/*
 * ProcessUtility hook
 */
static void
pgsp_ProcessUtility(PlannedStmt *pstmt, const char *queryString,
					bool readOnlyTree,
					ProcessUtilityContext context,
					ParamListInfo params, QueryEnvironment *queryEnv,
					DestReceiver *dest, QueryCompletion *qc)
{
	Node	   *parsetree = pstmt->utilityStmt;
	bool		enabled = pgsp_enabled(nesting_level);

	/*
	 * Even though we're not tracking plans for utility statements themselves,
	 * we must still increment the nesting level, to ensure that functions
	 * evaluated within it are not seen as top-level calls.  But don't do so
	 * for EXECUTE; that way, when control reaches pgsp_planner or
	 * pgsp_ExecutorStart, we will treat the costs as top-level if
	 * appropriate.  Likewise, don't bump for PREPARE, so that parse analysis
	 * will treat the statement as top-level if appropriate.
	 *
	 * To be absolutely certain we don't mess up the nesting level, evaluate
	 * the bump_level condition just once.
	 */
	bool		bump_level =
		!IsA(parsetree, ExecuteStmt) &&
		!IsA(parsetree, PrepareStmt);

	/*
	 * Force utility statements to get queryId zero. This matches what
	 * pg_stat_statements does in its ProcessUtility hook, and is necessary to
	 * allow joining on the queryId for pg_stat_plans_activity when
	 * pg_stat_statements is not enabled. If pg_stat_statements is loaded this
	 * is effectively a no-op, since either before our call of the hook, or
	 * afterwards, pgss_ProcessUtility will do the same thing.
	 */
	if (enabled)
		pstmt->queryId = UINT64CONST(0);

	if (bump_level)
		nesting_level++;
	PG_TRY();
	{
		if (prev_ProcessUtility)
			prev_ProcessUtility(pstmt, queryString, readOnlyTree,
								context, params, queryEnv,
								dest, qc);
		else
			standard_ProcessUtility(pstmt, queryString, readOnlyTree,
									context, params, queryEnv,
									dest, qc);
	}
	PG_FINALLY();
	{
		if (bump_level)
			nesting_level--;
	}
	PG_END_TRY();
}

/* Shared memory init callbacks */
static shmem_request_hook_type prev_shmem_request_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

/* Shared memory initialization when loading module */
static void
pgsp_shmem_request(void)
{
	if (prev_shmem_request_hook)
		prev_shmem_request_hook();

	// TODO: Anything we need to do here?
}

static void
pgsp_shmem_startup(void)
{
	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();

#if PG_VERSION_NUM < 180000
	StatsCustomShmemInit();
#endif
}

static ClientAuthentication_hook_type prev_ClientAuthentication_hook = NULL;

static void
pgsp_ClientAuthentication_hook(Port *port, int status)
{
	if (prev_ClientAuthentication_hook)
		prev_ClientAuthentication_hook(port, status);

#if PG_VERSION_NUM < 180000
	pgstat_custom_initialize();
#endif
}

/*
 * Module load callback
 */
void
_PG_init(void)
{
	/*
	 * In order to register for shared memory stats, we have to be loaded via
	 * shared_preload_libraries.  If not, fall out without hooking into any of
	 * the main system.  (We don't throw error here because it seems useful to
	 * allow the pg_stat_plans functions to be created even when the module
	 * isn't active.  The functions must protect themselves against being
	 * called then, however.)
	 */
	if (!process_shared_preload_libraries_in_progress)
		return;

	/*
	 * Inform the postmaster that we want to enable query_id calculation if
	 * compute_query_id is set to auto.
	 */
	EnableQueryId();

	/*
	 * Define (or redefine) custom GUC variables.
	 */
	DefineCustomIntVariable("pg_stat_plans.max",
							"Sets the maximum number of plans tracked by pg_stat_plans in shared memory.",
							NULL,
							&pgsp_max,
							5000,
							100,
							INT_MAX / 2,
							PGC_SIGHUP,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomIntVariable("pg_stat_plans.max_size",
							"Sets the maximum size of plan texts (in bytes) tracked by pg_stat_plans in shared memory.",
							NULL,
							&pgsp_max_size,
							2048,
							100,
							1048576,	/* 1MB hard limit */
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomEnumVariable("pg_stat_plans.track",
							 "Selects which plans are tracked by pg_stat_plans.",
							 NULL,
							 &pgsp_track,
							 PGSP_TRACK_TOP,
							 track_options,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	DefineCustomEnumVariable("pg_stat_plans.compress",
							 "Select compression used by pg_stat_plans.",
							 NULL,
							 &pgsp_compress,
							 PGSP_COMPRESS_NONE,
							 compress_options,
							 PGC_SUSET,
							 0,
							 NULL,
							 NULL,
							 NULL);

	MarkGUCPrefixReserved("pg_stat_plans");

	/*
	 * Install hooks.
	 */
	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = pgsp_post_parse_analyze;
	prev_planner_hook = planner_hook;
	planner_hook = pgsp_planner;
	prev_ExecutorStart = ExecutorStart_hook;
	ExecutorStart_hook = pgsp_ExecutorStart;
	prev_ExecutorRun = ExecutorRun_hook;
	ExecutorRun_hook = pgsp_ExecutorRun;
	prev_ExecutorFinish = ExecutorFinish_hook;
	ExecutorFinish_hook = pgsp_ExecutorFinish;
	prev_ExecutorEnd = ExecutorEnd_hook;
	ExecutorEnd_hook = pgsp_ExecutorEnd;
	prev_ProcessUtility = ProcessUtility_hook;
	ProcessUtility_hook = pgsp_ProcessUtility;

#if PG_VERSION_NUM < 180000
	prev_shmem_request_hook = shmem_request_hook;
	shmem_request_hook = pgsp_shmem_request;
	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pgsp_shmem_startup;
	prev_ClientAuthentication_hook = ClientAuthentication_hook;
	ClientAuthentication_hook = pgsp_ClientAuthentication_hook;
#endif

	pgstat_custom_register_kind(PGSTAT_KIND_PLANS, &plan_stats);
}

static bool
match_plans_entries(PgStatShared_HashEntry *entry, Datum match_data)
{
	return entry->key.kind == PGSTAT_KIND_PLANS;
}

/*
 * Reset statement statistics.
 */
Datum
pg_stat_plans_reset(PG_FUNCTION_ARGS)
{
	/* stats kind must be registered already */
	if (!pgstat_custom_get_kind_info(PGSTAT_KIND_PLANS))
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_stat_plans must be loaded via \"shared_preload_libraries\"")));

	pgstat_custom_drop_matching_entries(match_plans_entries, 0);

	/* Free plan text memory and allow cleanup of dropped entries */
	pgstat_gc_plan_memory();

	PG_RETURN_VOID();
}

Datum
pg_stat_plans_2_0(PG_FUNCTION_ARGS)
{
#define PG_STAT_PLANS_COLS 8
	bool		showplan = PG_GETARG_BOOL(0);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;
	Oid			userid = GetUserId();
	bool		is_allowed_role = false;

	dshash_seq_status hstat;
	PgStatShared_HashEntry *p;

	/*
	 * Superusers or roles with the privileges of pg_read_all_stats members
	 * are allowed
	 */
	is_allowed_role = has_privs_of_role(userid, ROLE_PG_READ_ALL_STATS);

	/* stats kind must be registered already */
	if (!pgstat_custom_get_kind_info(PGSTAT_KIND_PLANS))
		ereport(ERROR,
				(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
				 errmsg("pg_stat_plans must be loaded via \"shared_preload_libraries\"")));

	InitMaterializedSRF(fcinfo, 0);

	/* dshash entry is not modified, take shared lock */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, false);
	while ((p = dshash_seq_next(&hstat)) != NULL)
	{
		PgStat_StatPlanEntry *statent;
		Datum		values[PG_STAT_PLANS_COLS];
		bool		nulls[PG_STAT_PLANS_COLS];
		int			i = 0;

		if (p->dropped || p->key.kind != PGSTAT_KIND_PLANS)
			continue;

		memset(values, 0, sizeof(values));
		memset(nulls, 0, sizeof(nulls));

		statent = pgstat_custom_get_entry_data(p->key.kind, dsa_get_address(pgStatCustomLocal.dsa, p->body));

		values[i++] = ObjectIdGetDatum(statent->info.userid);
		values[i++] = ObjectIdGetDatum(p->key.dboid);
		values[i++] = BoolGetDatum(statent->info.toplevel);
		if (is_allowed_role || statent->info.userid == userid)
		{
			int64		queryid = statent->info.queryid;
			int64		planid = statent->info.planid;

			values[i++] = Int64GetDatumFast(queryid);
			values[i++] = Int64GetDatumFast(planid);
		}
		else
		{
			nulls[i++] = true;
			nulls[i++] = true;
		}
		values[i++] = Int64GetDatumFast(statent->exec_count);
		values[i++] = Float8GetDatumFast(statent->exec_time);

		if (showplan && (is_allowed_role || statent->info.userid == userid))
		{
			char	   *pstr = DsaPointerIsValid(statent->info.plan_text) ? dsa_get_address(pgStatCustomLocal.dsa, statent->info.plan_text) : NULL;

			if (pstr)
			{
				char	   *dec_pstr = pgsp_decompress_plan_text(pstr, statent->info.plan_text_size, statent->info.plan_text_compression);
				char	   *enc = pg_any_to_server(dec_pstr, strlen(dec_pstr), statent->info.plan_encoding);

				values[i++] = CStringGetTextDatum(enc);

				if (enc != dec_pstr)
					pfree(enc);
				pfree(dec_pstr);
			}
			else
			{
				nulls[i++] = true;
			}
		}
		else if (showplan)
		{
			values[i++] = CStringGetTextDatum("<insufficient privilege>");
		}
		else
		{
			nulls[i++] = true;
		}
		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);
	}
	dshash_seq_term(&hstat);

	return (Datum) 0;
}

#define HAS_PGSTAT_PERMISSIONS(role)	 (has_privs_of_role(GetUserId(), ROLE_PG_READ_ALL_STATS) || has_privs_of_role(GetUserId(), role))

/*
 * Returns plans of active PG backends.
 */
Datum
pg_stat_plans_2_0_get_activity(PG_FUNCTION_ARGS)
{
#if PG_VERSION_NUM >= 180000
#define PG_STAT_PLANS_GET_ACTIVITY_COLS	5
	int			num_backends = pgstat_fetch_stat_numbackends();
	int			curr_backend;
	int			pid = PG_ARGISNULL(0) ? -1 : PG_GETARG_INT32(0);
	ReturnSetInfo *rsinfo = (ReturnSetInfo *) fcinfo->resultinfo;

	InitMaterializedSRF(fcinfo, 0);

	/* 1-based index */
	for (curr_backend = 1; curr_backend <= num_backends; curr_backend++)
	{
		/* for each row */
		Datum		values[PG_STAT_PLANS_GET_ACTIVITY_COLS] = {0};
		bool		nulls[PG_STAT_PLANS_GET_ACTIVITY_COLS] = {0};
		LocalPgBackendStatus *local_beentry;
		PgBackendStatus *beentry;

		/* Get the next one in the list */
		local_beentry = pgstat_get_local_beentry_by_index(curr_backend);
		beentry = &local_beentry->backendStatus;

		/* If looking for specific PID, ignore all the others */
		if (pid != -1 && beentry->st_procpid != pid)
			continue;

		/* Values available to all callers */
		if (beentry->st_databaseid != InvalidOid)
			values[0] = ObjectIdGetDatum(beentry->st_databaseid);
		else
			nulls[0] = true;

		values[1] = Int32GetDatum(beentry->st_procpid);

		if (beentry->st_userid != InvalidOid)
			values[2] = ObjectIdGetDatum(beentry->st_userid);
		else
			nulls[2] = true;

		/* Values only available to role member or pg_read_all_stats */
		if (HAS_PGSTAT_PERMISSIONS(beentry->st_userid))
		{
			if (beentry->st_query_id == 0)
				nulls[3] = true;
			else
				values[3] = UInt64GetDatum(beentry->st_query_id);

			if (beentry->st_plan_id == 0)
				nulls[4] = true;
			else
				values[4] = UInt64GetDatum(beentry->st_plan_id);
		}
		else
		{
			/* No permissions to view data about this session */
			nulls[3] = true;
			nulls[4] = true;
		}

		tuplestore_putvalues(rsinfo->setResult, rsinfo->setDesc, values, nulls);

		/* If only a single backend was requested, and we found it, break. */
		if (pid != -1)
			break;
	}
#else
	elog(ERROR, "Not implemented, use of pg_stat_plans_get_activity requires Postgres 18+");
#endif

	return (Datum) 0;
}
