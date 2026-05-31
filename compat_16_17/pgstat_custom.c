/*--------------------------------------------------------------------------
 *
 * pgstat_custom.c
 *		Compatibility layer for pluggable cumulative statistics on older
 *      releases.
 *
 * Portions Copyright (c) 1996-2024, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * IDENTIFICATION
 *		pgstat_custom.c
 *
 * -------------------------------------------------------------------------
 */

#include "postgres.h"

#if PG_VERSION_NUM < 180000

#include "access/xact.h"
#include "utils/memutils.h"
#include "utils/timestamp.h"
#include "storage/ipc.h"
#include "storage/shmem.h"

#include "pgstat_custom.h"

/* Range of IDs allowed, for built-in and custom kinds */
#define PGSTAT_KIND_MIN	1		/* Minimum ID allowed */
#define PGSTAT_KIND_MAX	32		/* Maximum ID allowed */

#define PGSTAT_KIND_BUILTIN_MIN 0
#define PGSTAT_KIND_BUILTIN_MAX 23
#define PGSTAT_KIND_BUILTIN_SIZE (PGSTAT_KIND_BUILTIN_MAX + 1)

/* Custom stats kinds */

/* Range of IDs allowed for custom stats kinds */
#define PGSTAT_KIND_CUSTOM_MIN	24
#define PGSTAT_KIND_CUSTOM_MAX	PGSTAT_KIND_MAX
#define PGSTAT_KIND_CUSTOM_SIZE	(PGSTAT_KIND_CUSTOM_MAX - PGSTAT_KIND_CUSTOM_MIN + 1)

static inline bool
pgstat_custom_is_kind_builtin(PgStat_Kind kind)
{
	return kind >= PGSTAT_KIND_BUILTIN_MIN && kind <= PGSTAT_KIND_BUILTIN_MAX;
}

static inline bool
pgstat_custom_is_kind_custom(PgStat_Kind kind)
{
	return kind >= PGSTAT_KIND_CUSTOM_MIN && kind <= PGSTAT_KIND_CUSTOM_MAX;
}

/* Copied from pgstat.c */

/* ----------
 * Timer definitions.
 *
 * In milliseconds.
 * ----------
 */

/* minimum interval non-forced stats flushes.*/
#define PGSTAT_MIN_INTERVAL			1000
/* how long until to block flushing pending stats updates */
#define PGSTAT_MAX_INTERVAL			60000
/* when to call pgstat_report_stat() again, even when idle */
#define PGSTAT_IDLE_INTERVAL		10000

static bool pgstat_custom_flush_pending_entries(bool nowait);


/* ----------
 * state shared with pgstat_*.c
 * ----------
 */

PgStat_LocalState pgStatCustomLocal;

/* ----------
 * Local data
 *
 * NB: There should be only variables related to stats infrastructure here,
 * not for specific kinds of stats.
 * ----------
 */

/*
 * Memory contexts containing the pgStatEntryRefHash table, the
 * pgStatSharedRef entries, and pending data respectively. Mostly to make it
 * easier to track / attribute memory usage.
 */

static MemoryContext pgStatCustomPendingContext = NULL;

/*
 * Backend local list of PgStat_EntryRef with unflushed pending stats.
 *
 * Newly pending entries should only ever be added to the end of the list,
 * otherwise pgstat_flush_pending_entries() might not see them immediately.
 */
static dlist_head pgStatCustomPending = DLIST_STATIC_INIT(pgStatCustomPending);

/*
 * Force the next stats flush to happen regardless of
 * PGSTAT_MIN_INTERVAL. Useful in test scripts.
 */
static bool pgStatCustomForceNextFlush = false;


/*
 * For assertions that check pgstat is not used before initialization / after
 * shutdown.
 */
#ifdef USE_ASSERT_CHECKING
static bool pgstat_custom_is_initialized = false;
static bool pgstat_custom_is_shutdown = false;
#endif

/*
 * Information about custom statistics kinds.
 *
 * These are saved in a different array than the built-in kinds to save
 * in clarity with the initializations.
 *
 * Indexed by PGSTAT_KIND_CUSTOM_MIN, of size PGSTAT_KIND_CUSTOM_SIZE.
 */
static const PgStat_KindInfo **pgstat_kind_custom_infos = NULL;


/*
 * pgstat_before_server_shutdown() needs to be called by exactly one process
 * during regular server shutdowns. Otherwise all stats will be lost.
 *
 * We currently only write out stats for proc_exit(0). We might want to change
 * that at some point... But right now pgstat_discard_stats() would be called
 * during the start after a disorderly shutdown, anyway.
 */
static void
pgstat_custom_before_server_shutdown(int code, Datum arg)
{
	Assert(pgStatCustomLocal.shmem != NULL);
	Assert(!pgStatCustomLocal.shmem->is_shutdown);

	/*
	 * Stats should only be reported after pgstat_custom_initialize() and before
	 * pgstat_custom_shutdown(). This is a convenient point to catch most violations
	 * of this rule.
	 */
	Assert(pgstat_custom_is_initialized && !pgstat_custom_is_shutdown);

	/* flush out our own pending changes before writing out */
	pgstat_custom_report_stat(true);

	/*
	 * Only write out file during normal shutdown. Don't even signal that
	 * we've shutdown during irregular shutdowns, because the shutdown
	 * sequence isn't coordinated to ensure this backend shuts down last.
	 */
	if (code == 0)
	{
		pgStatCustomLocal.shmem->is_shutdown = true;
		/*pgstat_write_statsfile();*/
	}
}


/* ------------------------------------------------------------
 * Backend initialization / shutdown functions
 * ------------------------------------------------------------
 */

/*
 * Shut down a single backend's statistics reporting at process exit.
 *
 * Flush out any remaining statistics counts.  Without this, operations
 * triggered during backend exit (such as temp table deletions) won't be
 * counted.
 */
static void
pgstat_custom_shutdown_hook(int code, Datum arg)
{
	Assert(!pgstat_custom_is_shutdown);
	Assert(IsUnderPostmaster || !IsPostmasterEnvironment);

	/*
	 * If we got as far as discovering our own database ID, we can flush out
	 * what we did so far.  Otherwise, we'd be reporting an invalid database
	 * ID, so forget it.  (This means that accesses to pg_database during
	 * failed backend starts might never get counted.)
	 */
	/*if (OidIsValid(MyDatabaseId))
		pgstat_report_disconnect(MyDatabaseId);*/

	pgstat_custom_report_stat(true);

	/* there shouldn't be any pending changes left */
	Assert(dlist_is_empty(&pgStatCustomPending));
	dlist_init(&pgStatCustomPending);

	/* drop the backend stats entry */
	/*if (!pgstat_drop_entry(PGSTAT_KIND_BACKEND, InvalidOid, MyProcNumber))
		pgstat_request_entry_refs_gc();*/

	pgstat_custom_detach_shmem();

#ifdef USE_ASSERT_CHECKING
	pgstat_custom_is_shutdown = true;
#endif
}

/*
 * Initialize pgstats state, and set up our on-proc-exit hook. Called from
 * BaseInit().
 *
 * NOTE: MyDatabaseId isn't set yet; so the shutdown hook has to be careful.
 */
void
pgstat_custom_initialize(void)
{
	Assert(!pgstat_custom_is_initialized);

	pgstat_custom_attach_shmem();

	/*pgstat_custom_init_snapshot_fixed();*/

	/* Backend initialization callbacks */
	/*for (PgStat_Kind kind = PGSTAT_KIND_MIN; kind <= PGSTAT_KIND_MAX; kind++)
	{
		const PgStat_KindInfo *kind_info = pgstat_custom_get_kind_info(kind);

		if (kind_info == NULL || kind_info->init_backend_cb == NULL)
			continue;

		kind_info->init_backend_cb();
	}*/

	/* Set up a process-exit hook to clean up */
	before_shmem_exit(pgstat_custom_shutdown_hook, 0);

#ifdef USE_ASSERT_CHECKING
	pgstat_custom_is_initialized = true;
#endif
}

/* ------------------------------------------------------------
 * Public functions used by backends follow
 * ------------------------------------------------------------
 */

/*
 * Must be called by processes that performs DML: tcop/postgres.c, logical
 * receiver processes, SPI worker, etc. to flush pending statistics updates to
 * shared memory.
 *
 * Unless called with 'force', pending stats updates are flushed happen once
 * per PGSTAT_MIN_INTERVAL (1000ms). When not forced, stats flushes do not
 * block on lock acquisition, except if stats updates have been pending for
 * longer than PGSTAT_MAX_INTERVAL (60000ms).
 *
 * Whenever pending stats updates remain at the end of pgstat_report_stat() a
 * suggested idle timeout is returned. Currently this is always
 * PGSTAT_IDLE_INTERVAL (10000ms). Callers can use the returned time to set up
 * a timeout after which to call pgstat_report_stat(true), but are not
 * required to do so.
 *
 * Note that this is called only when not within a transaction, so it is fair
 * to use transaction stop time as an approximation of current time.
 */
long
pgstat_custom_report_stat(bool force)
{
	static TimestampTz pending_since = 0;
	static TimestampTz last_flush = 0;
	bool		partial_flush;
	TimestampTz now;
	bool		nowait;

	pgstat_custom_assert_is_up();
	//Assert(!IsTransactionOrTransactionBlock());

	/* "absorb" the forced flush even if there's nothing to flush */
	if (pgStatCustomForceNextFlush)
	{
		force = true;
		pgStatCustomForceNextFlush = false;
	}

	/* Don't expend a clock check if nothing to do */
	if (dlist_is_empty(&pgStatCustomPending)/* &&
		!pgstat_report_fixed*/)
	{
		return 0;
	}

	/*
	 * There should never be stats to report once stats are shut down. Can't
	 * assert that before the checks above, as there is an unconditional
	 * pgstat_report_stat() call in pgstat_shutdown_hook() - which at least
	 * the process that ran pgstat_before_server_shutdown() will still call.
	 */
	Assert(!pgStatCustomLocal.shmem->is_shutdown);

	if (force)
	{
		/*
		 * Stats reports are forced either when it's been too long since stats
		 * have been reported or in processes that force stats reporting to
		 * happen at specific points (including shutdown). In the former case
		 * the transaction stop time might be quite old, in the latter it
		 * would never get cleared.
		 */
		now = GetCurrentTimestamp();
	}
	else
	{
		now = GetCurrentTransactionStopTimestamp();

		if (pending_since > 0 &&
			TimestampDifferenceExceeds(pending_since, now, PGSTAT_MAX_INTERVAL))
		{
			/* don't keep pending updates longer than PGSTAT_MAX_INTERVAL */
			force = true;
		}
		else if (last_flush > 0 &&
				 !TimestampDifferenceExceeds(last_flush, now, PGSTAT_MIN_INTERVAL))
		{
			/* don't flush too frequently */
			if (pending_since == 0)
				pending_since = now;

			return PGSTAT_IDLE_INTERVAL;
		}
	}

	/*pgstat_update_dbstats(now);*/

	/* don't wait for lock acquisition when !force */
	nowait = !force;

	partial_flush = false;

	/* flush of variable-numbered stats tracked in pending entries list */
	partial_flush |= pgstat_custom_flush_pending_entries(nowait);

	/* flush of other stats kinds */
	/*if (pgstat_report_fixed)
	{
		for (PgStat_Kind kind = PGSTAT_KIND_MIN; kind <= PGSTAT_KIND_MAX; kind++)
		{
			const PgStat_KindInfo *kind_info = pgstat_get_kind_info(kind);

			if (!kind_info)
				continue;
			if (!kind_info->flush_static_cb)
				continue;

			partial_flush |= kind_info->flush_static_cb(nowait);
		}
	}*/

	last_flush = now;

	/*
	 * If some of the pending stats could not be flushed due to lock
	 * contention, let the caller know when to retry.
	 */
	if (partial_flush)
	{
		/* force should have prevented us from getting here */
		Assert(!force);

		/* remember since when stats have been pending */
		if (pending_since == 0)
			pending_since = now;

		return PGSTAT_IDLE_INTERVAL;
	}

	pending_since = 0;
/*	pgstat_report_fixed = false;*/

	return 0;
}

/* ------------------------------------------------------------
 * Backend-local pending stats infrastructure
 * ------------------------------------------------------------
 */

/*
 * Returns the appropriate PgStat_EntryRef, preparing it to receive pending
 * stats if not already done.
 *
 * If created_entry is non-NULL, it'll be set to true if the entry is newly
 * created, false otherwise.
 */
PgStat_EntryRef *
pgstat_custom_prep_pending_entry(PgStat_Kind kind, Oid dboid, Oid objid, bool *created_entry)
{
	PgStat_EntryRef *entry_ref;

	/* need to be able to flush out */
	Assert(pgstat_custom_get_kind_info(kind)->flush_pending_cb != NULL);

	if (unlikely(!pgStatCustomPendingContext))
	{
		pgStatCustomPendingContext =
			AllocSetContextCreate(TopMemoryContext,
								  "PgStat Custom Pending",
								  ALLOCSET_SMALL_SIZES);
	}

	entry_ref = pgstat_custom_get_entry_ref(kind, dboid, objid,
									 true, created_entry);

	if (entry_ref->pending == NULL)
	{
		size_t		entrysize = pgstat_custom_get_kind_info(kind)->pending_size;

		Assert(entrysize != (size_t) -1);

		entry_ref->pending = MemoryContextAllocZero(pgStatCustomPendingContext, entrysize);
		dlist_push_tail(&pgStatCustomPending, &entry_ref->pending_node);
	}

	return entry_ref;
}

/*
 * Return an existing stats entry, or NULL.
 *
 * This should only be used for helper function for pgstatfuncs.c - outside of
 * that it shouldn't be needed.
 */
PgStat_EntryRef *
pgstat_custom_fetch_pending_entry(PgStat_Kind kind, Oid dboid, Oid objid)
{
	PgStat_EntryRef *entry_ref;

	entry_ref = pgstat_custom_get_entry_ref(kind, dboid, objid, false, NULL);

	if (entry_ref == NULL || entry_ref->pending == NULL)
		return NULL;

	return entry_ref;
}

void
pgstat_custom_delete_pending_entry(PgStat_EntryRef *entry_ref)
{
	PgStat_Kind kind = entry_ref->shared_entry->key.kind;
	const PgStat_KindInfo *kind_info = pgstat_custom_get_kind_info(kind);
	void	   *pending_data = entry_ref->pending;

	Assert(pending_data != NULL);
	/* !fixed_amount stats should be handled explicitly */
	Assert(!pgstat_custom_get_kind_info(kind)->fixed_amount);

	if (kind_info->delete_pending_cb)
		kind_info->delete_pending_cb(entry_ref);

	pfree(pending_data);
	entry_ref->pending = NULL;

	dlist_delete(&entry_ref->pending_node);
}

/*
 * Flush out pending variable-numbered stats.
 */
static bool
pgstat_custom_flush_pending_entries(bool nowait)
{
	bool		have_pending = false;
	dlist_node *cur = NULL;

	/*
	 * Need to be a bit careful iterating over the list of pending entries.
	 * Processing a pending entry may queue further pending entries to the end
	 * of the list that we want to process, so a simple iteration won't do.
	 * Further complicating matters is that we want to delete the current
	 * entry in each iteration from the list if we flushed successfully.
	 *
	 * So we just keep track of the next pointer in each loop iteration.
	 */
	if (!dlist_is_empty(&pgStatCustomPending))
		cur = dlist_head_node(&pgStatCustomPending);

	while (cur)
	{
		PgStat_EntryRef *entry_ref =
			dlist_container(PgStat_EntryRef, pending_node, cur);
		PgStat_HashKey key = entry_ref->shared_entry->key;
		PgStat_Kind kind = key.kind;
		const PgStat_KindInfo *kind_info = pgstat_custom_get_kind_info(kind);
		bool		did_flush;
		dlist_node *next;

		Assert(!kind_info->fixed_amount);
		Assert(kind_info->flush_pending_cb != NULL);

		/* flush the stats, if possible */
		did_flush = kind_info->flush_pending_cb(entry_ref, nowait);

		Assert(did_flush || nowait);

		/* determine next entry, before deleting the pending entry */
		if (dlist_has_next(&pgStatCustomPending, cur))
			next = dlist_next_node(&pgStatCustomPending, cur);
		else
			next = NULL;

		/* if successfully flushed, remove entry */
		if (did_flush)
			pgstat_custom_delete_pending_entry(entry_ref);
		else
			have_pending = true;

		cur = next;
	}

	Assert(dlist_is_empty(&pgStatCustomPending) == !have_pending);

	return have_pending;
}

/*
 * Register a new stats kind.
 *
 * PgStat_Kinds must be globally unique across all extensions. Refer
 * to https://wiki.postgresql.org/wiki/CustomCumulativeStats to reserve a
 * unique ID for your extension, to avoid conflicts with other extension
 * developers. During development, use PGSTAT_KIND_EXPERIMENTAL to avoid
 * needlessly reserving a new ID.
 */
void
pgstat_custom_register_kind(PgStat_Kind kind, const PgStat_KindInfo *kind_info)
{
	uint32		idx = kind - PGSTAT_KIND_CUSTOM_MIN;

	if (kind_info->name == NULL || strlen(kind_info->name) == 0)
		ereport(ERROR,
				(errmsg("custom cumulative statistics name is invalid"),
				 errhint("Provide a non-empty name for the custom cumulative statistics.")));

	if (!pgstat_custom_is_kind_custom(kind))
		ereport(ERROR, (errmsg("custom cumulative statistics ID %u is out of range", kind),
						errhint("Provide a custom cumulative statistics ID between %u and %u.",
								PGSTAT_KIND_CUSTOM_MIN, PGSTAT_KIND_CUSTOM_MAX)));

	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errmsg("failed to register custom cumulative statistics \"%s\" with ID %u", kind_info->name, kind),
				 errdetail("Custom cumulative statistics must be registered while initializing modules in \"shared_preload_libraries\".")));

	/*
	 * Check some data for fixed-numbered stats.
	 */
	if (kind_info->fixed_amount)
	{
		if (kind_info->shared_size == 0)
			ereport(ERROR,
					(errmsg("custom cumulative statistics property is invalid"),
					 errhint("Custom cumulative statistics require a shared memory size for fixed-numbered objects.")));
	}

	/*
	 * If pgstat_kind_custom_infos is not available yet, allocate it.
	 */
	if (pgstat_kind_custom_infos == NULL)
	{
		pgstat_kind_custom_infos = (const PgStat_KindInfo **)
			MemoryContextAllocZero(TopMemoryContext,
								   sizeof(PgStat_KindInfo *) * PGSTAT_KIND_CUSTOM_SIZE);
	}

	if (pgstat_kind_custom_infos[idx] != NULL &&
		pgstat_kind_custom_infos[idx]->name != NULL)
		ereport(ERROR,
				(errmsg("failed to register custom cumulative statistics \"%s\" with ID %u", kind_info->name, kind),
				 errdetail("Custom cumulative statistics \"%s\" already registered with the same ID.",
						   pgstat_kind_custom_infos[idx]->name)));

	/* check for existing custom stats with the same name */
	for (PgStat_Kind existing_kind = PGSTAT_KIND_CUSTOM_MIN; existing_kind <= PGSTAT_KIND_CUSTOM_MAX; existing_kind++)
	{
		uint32		existing_idx = existing_kind - PGSTAT_KIND_CUSTOM_MIN;

		if (pgstat_kind_custom_infos[existing_idx] == NULL)
			continue;
		if (!pg_strcasecmp(pgstat_kind_custom_infos[existing_idx]->name, kind_info->name))
			ereport(ERROR,
					(errmsg("failed to register custom cumulative statistics \"%s\" with ID %u", kind_info->name, kind),
					 errdetail("Existing cumulative statistics with ID %u has the same name.", existing_kind)));
	}

	/* Register it */
	pgstat_kind_custom_infos[idx] = kind_info;
	ereport(LOG,
			(errmsg("registered custom cumulative statistics \"%s\" with ID %u",
					kind_info->name, kind)));
}

/*
 * Stats should only be reported after pgstat_initialize() and before
 * pgstat_shutdown(). This check is put in a few central places to catch
 * violations of this rule more easily.
 */
#ifdef USE_ASSERT_CHECKING
void
pgstat_custom_assert_is_up(void)
{
	Assert(pgstat_custom_is_initialized && !pgstat_custom_is_shutdown);
}
#endif

const PgStat_KindInfo *
pgstat_custom_get_kind_info(PgStat_Kind kind)
{
	if (pgstat_custom_is_kind_builtin(kind))
		elog(ERROR, "Unexpected built-in kind (only custom kind numbers should be used): %d", kind);

	if (pgstat_custom_is_kind_custom(kind))
	{
		uint32		idx = kind - PGSTAT_KIND_CUSTOM_MIN;

		if (pgstat_kind_custom_infos == NULL ||
			pgstat_kind_custom_infos[idx] == NULL)
			return NULL;
		return pgstat_kind_custom_infos[idx];
	}

	return NULL;
}

/* Copied from pgstat_shmem.c */

#define PGSTAT_ENTRY_REF_HASH_SIZE	128

/* hash table entry for finding the PgStat_EntryRef for a key */
typedef struct PgStat_EntryRefHashEntry
{
	PgStat_HashKey key;			/* hash key */
	char		status;			/* for simplehash use */
	PgStat_EntryRef *entry_ref;
} PgStat_EntryRefHashEntry;


/* for references to shared statistics entries */
#define SH_PREFIX pgstat_custom_entry_ref_hash
#define SH_ELEMENT_TYPE PgStat_EntryRefHashEntry
#define SH_KEY_TYPE PgStat_HashKey
#define SH_KEY key
#define SH_HASH_KEY(tb, key) \
	pgstat_hash_hash_key(&key, sizeof(PgStat_HashKey), NULL)
#define SH_EQUAL(tb, a, b) \
	pgstat_cmp_hash_key(&a, &b, sizeof(PgStat_HashKey), NULL) == 0
#define SH_SCOPE static inline
#define SH_DEFINE
#define SH_DECLARE
#include "lib/simplehash.h"

/* parameter for the shared hash */
static const dshash_parameters dsh_params = {
	sizeof(PgStat_HashKey),
	sizeof(PgStatShared_HashEntry),
	pgstat_cmp_hash_key,
	pgstat_hash_hash_key,
#if PG_VERSION_NUM >= 170000
	dshash_memcpy,
#endif
	LWTRANCHE_PGSTATS_HASH
};

static void pgstat_custom_free_entry(PgStatShared_HashEntry *shent, dshash_seq_status *hstat);
static void pgstat_custom_release_entry_ref(PgStat_HashKey key, PgStat_EntryRef *entry_ref, bool discard_pending);
static bool pgstat_custom_need_entry_refs_gc(void);
static void pgstat_custom_gc_entry_refs(void);
static void pgstat_custom_release_all_entry_refs(bool discard_pending);
typedef bool (*ReleaseMatchCB) (PgStat_EntryRefHashEntry *, Datum data);
static void pgstat_custom_release_matching_entry_refs(bool discard_pending, ReleaseMatchCB match, Datum match_data);

static void pgstat_custom_setup_memcxt(void);

/*
 * Backend local references to shared stats entries. If there are pending
 * updates to a stats entry, the PgStat_EntryRef is added to the pgStatPending
 * list.
 *
 * When a stats entry is dropped each backend needs to release its reference
 * to it before the memory can be released. To trigger that
 * pgStatCustomLocal.shmem->gc_request_count is incremented - which each backend
 * compares to their copy of pgStatSharedRefAge on a regular basis.
 */
static pgstat_custom_entry_ref_hash_hash *pgStatCustomEntryRefHash = NULL;
static int	pgStatCustomSharedRefAge = 0; /* cache age of pgStatCustomLocal.shmem */

/*
 * Memory contexts containing the pgStatCustomEntryRefHash table and the
 * pgStatSharedRef entries respectively. Kept separate to make it easier to
 * track / attribute memory usage.
 */
static MemoryContext pgStatCustomSharedRefContext = NULL;
static MemoryContext pgStatCustomEntryRefHashContext = NULL;

/* ------------------------------------------------------------
 * Public functions called from extension init follow
 * ------------------------------------------------------------
 */

/*
 * The size of the shared memory allocation for stats stored in the shared
 * stats hash table. This allocation will be done as part of the main shared
 * memory, rather than dynamic shared memory, allowing it to be initialized in
 * postmaster.
 */
static Size
pgstat_custom_dsa_init_size(void)
{
	Size		sz;

	/*
	 * The dshash header / initial buckets array needs to fit into "plain"
	 * shared memory, but it's beneficial to not need dsm segments
	 * immediately. A size of 256kB seems works well and is not
	 * disproportional compared to other constant sized shared memory
	 * allocations. NB: To avoid DSMs further, the user can configure
	 * min_dynamic_shared_memory.
	 */
	sz = 256 * 1024;
	Assert(dsa_minimum_size() <= sz);
	return MAXALIGN(sz);
}

/*
 * Compute shared memory space needed for cumulative statistics
 */
static Size
StatsCustomShmemSize(void)
{
	Size		sz;

	sz = MAXALIGN(sizeof(PgStat_ShmemControl));
	sz = add_size(sz, pgstat_custom_dsa_init_size());

	/* Add shared memory for all the custom fixed-numbered statistics */
	for (PgStat_Kind kind = PGSTAT_KIND_CUSTOM_MIN; kind <= PGSTAT_KIND_CUSTOM_MAX; kind++)
	{
		const PgStat_KindInfo *kind_info = pgstat_custom_get_kind_info(kind);

		if (!kind_info)
			continue;
		if (!kind_info->fixed_amount)
			continue;

		Assert(kind_info->shared_size != 0);

		sz += MAXALIGN(kind_info->shared_size);
	}

	return sz;
}

/*
 * Initialize cumulative statistics system during startup
 */
void
StatsCustomShmemInit(void)
{
	bool		found;
	Size		sz;

	sz = StatsCustomShmemSize();
	pgStatCustomLocal.shmem = (PgStat_ShmemControl *)
		ShmemInitStruct("Shared Memory Stats Custom", sz, &found);

	if (!IsUnderPostmaster)
	{
		dsa_area   *dsa;
		dshash_table *dsh;
		PgStat_ShmemControl *ctl = pgStatCustomLocal.shmem;
		char	   *p = (char *) ctl;

		Assert(!found);

		/* the allocation of pgStatCustomLocal.shmem itself */
		p += MAXALIGN(sizeof(PgStat_ShmemControl));

		/*
		 * Create a small dsa allocation in plain shared memory. This is
		 * required because postmaster cannot use dsm segments. It also
		 * provides a small efficiency win.
		 */
		ctl->raw_dsa_area = p;
		p += MAXALIGN(pgstat_custom_dsa_init_size());
		dsa = dsa_create_in_place(ctl->raw_dsa_area,
								  pgstat_custom_dsa_init_size(),
								  LWTRANCHE_PGSTATS_DSA, NULL);
		dsa_pin(dsa);

		/*
		 * To ensure dshash is created in "plain" shared memory, temporarily
		 * limit size of dsa to the initial size of the dsa.
		 */
		dsa_set_size_limit(dsa, pgstat_custom_dsa_init_size());

		/*
		 * With the limit in place, create the dshash table. XXX: It'd be nice
		 * if there were dshash_create_in_place().
		 */
		dsh = dshash_create(dsa, &dsh_params, NULL);
		ctl->hash_handle = dshash_get_hash_table_handle(dsh);

		/* lift limit set above */
		dsa_set_size_limit(dsa, -1);

		/*
		 * Postmaster will never access these again, thus free the local
		 * dsa/dshash references.
		 */
		dshash_detach(dsh);
		dsa_detach(dsa);

		pg_atomic_init_u64(&ctl->gc_request_count, 1);

		/* initialize fixed-numbered stats */
		/*for (PgStat_Kind kind = PGSTAT_KIND_MIN; kind <= PGSTAT_KIND_MAX; kind++)
		{
			const PgStat_KindInfo *kind_info = pgstat_custom_get_kind_info(kind);
			char	   *ptr;

			if (!kind_info || !kind_info->fixed_amount)
				continue;

			if (pgstat_custom_is_kind_builtin(kind))
				ptr = ((char *) ctl) + kind_info->shared_ctl_off;
			else
			{
				int			idx = kind - PGSTAT_KIND_CUSTOM_MIN;

				Assert(kind_info->shared_size != 0);
				ctl->custom_data[idx] = ShmemAlloc(kind_info->shared_size);
				ptr = ctl->custom_data[idx];
			}

			kind_info->init_shmem_cb(ptr);
		}*/
	}
	else
	{
		Assert(found);
	}
}

void
pgstat_custom_attach_shmem(void)
{
	MemoryContext oldcontext;

	Assert(pgStatCustomLocal.dsa == NULL);

	/* stats shared memory persists for the backend lifetime */
	oldcontext = MemoryContextSwitchTo(TopMemoryContext);

	pgStatCustomLocal.dsa = dsa_attach_in_place(pgStatCustomLocal.shmem->raw_dsa_area,
										  NULL);
	dsa_pin_mapping(pgStatCustomLocal.dsa);

	pgStatCustomLocal.shared_hash = dshash_attach(pgStatCustomLocal.dsa, &dsh_params,
											pgStatCustomLocal.shmem->hash_handle,
											NULL);

	MemoryContextSwitchTo(oldcontext);
}

void
pgstat_custom_detach_shmem(void)
{
	Assert(pgStatCustomLocal.dsa);

	/* we shouldn't leave references to shared stats */
	pgstat_custom_release_all_entry_refs(false);

	dshash_detach(pgStatCustomLocal.shared_hash);
	pgStatCustomLocal.shared_hash = NULL;

	dsa_detach(pgStatCustomLocal.dsa);

	/*
	 * dsa_detach() does not decrement the DSA reference count as no segment
	 * was provided to dsa_attach_in_place(), causing no cleanup callbacks to
	 * be registered.  Hence, release it manually now.
	 */
	dsa_release_in_place(pgStatCustomLocal.shmem->raw_dsa_area);

	pgStatCustomLocal.dsa = NULL;
}

/* ------------------------------------------------------------
 * Maintenance of shared memory stats entries
 * ------------------------------------------------------------
 */

/*
 * Initialize entry newly-created.
 *
 * Returns NULL in the event of an allocation failure, so as callers can
 * take cleanup actions as the entry initialized is already inserted in the
 * shared hashtable.
 */
static PgStatShared_Common *
pgstat_custom_init_entry(PgStat_Kind kind,
				  PgStatShared_HashEntry *shhashent)
{
	/* Create new stats entry. */
	dsa_pointer chunk;
	PgStatShared_Common *shheader;

	/*
	 * Initialize refcount to 1, marking it as valid / not dropped. The entry
	 * can't be freed before the initialization because it can't be found as
	 * long as we hold the dshash partition lock. Caller needs to increase
	 * further if a longer lived reference is needed.
	 */
	pg_atomic_init_u32(&shhashent->refcount, 1);

	/*
	 * Initialize "generation" to 0, as freshly created.
	 */
	pg_atomic_init_u32(&shhashent->generation, 0);
	shhashent->dropped = false;

	chunk = dsa_allocate_extended(pgStatCustomLocal.dsa,
								  pgstat_custom_get_kind_info(kind)->shared_size,
								  DSA_ALLOC_ZERO | DSA_ALLOC_NO_OOM);
	if (chunk == InvalidDsaPointer)
		return NULL;

	shheader = dsa_get_address(pgStatCustomLocal.dsa, chunk);
	shheader->magic = 0xdeadbeef;

	/* Link the new entry from the hash entry. */
	shhashent->body = chunk;

	LWLockInitialize(&shheader->lock, LWTRANCHE_PGSTATS_DATA);

	return shheader;
}

static PgStatShared_Common *
pgstat_custom_reinit_entry(PgStat_Kind kind, PgStatShared_HashEntry *shhashent)
{
	PgStatShared_Common *shheader;

	shheader = dsa_get_address(pgStatCustomLocal.dsa, shhashent->body);

	/* mark as not dropped anymore */
	pg_atomic_fetch_add_u32(&shhashent->refcount, 1);

	/*
	 * Increment "generation", to let any backend with local references know
	 * that what they point to is outdated.
	 */
	pg_atomic_fetch_add_u32(&shhashent->generation, 1);
	shhashent->dropped = false;

	/* reinitialize content */
	Assert(shheader->magic == 0xdeadbeef);
	memset(pgstat_custom_get_entry_data(kind, shheader), 0,
		   pgstat_custom_get_entry_len(kind));

	return shheader;
}

static void
pgstat_custom_setup_shared_refs(void)
{
	if (likely(pgStatCustomEntryRefHash != NULL))
		return;

	pgStatCustomEntryRefHash =
		pgstat_custom_entry_ref_hash_create(pgStatCustomEntryRefHashContext,
									 PGSTAT_ENTRY_REF_HASH_SIZE, NULL);
	pgStatCustomSharedRefAge = pg_atomic_read_u64(&pgStatCustomLocal.shmem->gc_request_count);
	Assert(pgStatCustomSharedRefAge != 0);
}

/*
 * Helper function for pgstat_get_entry_ref().
 */
static void
pgstat_custom_acquire_entry_ref(PgStat_EntryRef *entry_ref,
						 PgStatShared_HashEntry *shhashent,
						 PgStatShared_Common *shheader)
{
	Assert(shheader->magic == 0xdeadbeef);
	Assert(pg_atomic_read_u32(&shhashent->refcount) > 0);

	pg_atomic_fetch_add_u32(&shhashent->refcount, 1);

	dshash_release_lock(pgStatCustomLocal.shared_hash, shhashent);

	entry_ref->shared_stats = shheader;
	entry_ref->shared_entry = shhashent;
	entry_ref->generation = pg_atomic_read_u32(&shhashent->generation);
}

/*
 * Helper function for pgstat_get_entry_ref().
 */
static bool
pgstat_custom_get_entry_ref_cached(PgStat_HashKey key, PgStat_EntryRef **entry_ref_p)
{
	bool		found;
	PgStat_EntryRefHashEntry *cache_entry;

	/*
	 * We immediately insert a cache entry, because it avoids 1) multiple
	 * hashtable lookups in case of a cache miss 2) having to deal with
	 * out-of-memory errors after incrementing PgStatShared_Common->refcount.
	 */

	cache_entry = pgstat_custom_entry_ref_hash_insert(pgStatCustomEntryRefHash, key, &found);

	if (!found || !cache_entry->entry_ref)
	{
		PgStat_EntryRef *entry_ref;

		cache_entry->entry_ref = entry_ref =
			MemoryContextAlloc(pgStatCustomSharedRefContext,
							   sizeof(PgStat_EntryRef));
		entry_ref->shared_stats = NULL;
		entry_ref->shared_entry = NULL;
		entry_ref->pending = NULL;

		found = false;
	}
	else if (cache_entry->entry_ref->shared_stats == NULL)
	{
		Assert(cache_entry->entry_ref->pending == NULL);
		found = false;
	}
	else
	{
		PgStat_EntryRef *entry_ref PG_USED_FOR_ASSERTS_ONLY;

		entry_ref = cache_entry->entry_ref;
		Assert(entry_ref->shared_entry != NULL);
		Assert(entry_ref->shared_stats != NULL);

		Assert(entry_ref->shared_stats->magic == 0xdeadbeef);
		/* should have at least our reference */
		Assert(pg_atomic_read_u32(&entry_ref->shared_entry->refcount) > 0);
	}

	*entry_ref_p = cache_entry->entry_ref;
	return found;
}

/*
 * Get a shared stats reference. If create is true, the shared stats object is
 * created if it does not exist.
 *
 * When create is true, and created_entry is non-NULL, it'll be set to true
 * if the entry is newly created, false otherwise.
 */
PgStat_EntryRef *
pgstat_custom_get_entry_ref(PgStat_Kind kind, Oid dboid, Oid objid, bool create,
					 bool *created_entry)
{
	PgStat_HashKey key;
	PgStatShared_HashEntry *shhashent;
	PgStatShared_Common *shheader = NULL;
	PgStat_EntryRef *entry_ref;

	/* clear padding */
	memset(&key, 0, sizeof(struct PgStat_HashKey));

	key.kind = kind;
	key.dboid = dboid;
	key.objoid = objid;

	/*
	 * passing in created_entry only makes sense if we possibly could create
	 * entry.
	 */
	Assert(create || created_entry == NULL);
	pgstat_custom_assert_is_up();
	Assert(pgStatCustomLocal.shared_hash != NULL);
	Assert(!pgStatCustomLocal.shmem->is_shutdown);

	pgstat_custom_setup_memcxt();
	pgstat_custom_setup_shared_refs();

	if (created_entry != NULL)
		*created_entry = false;

	/*
	 * Check if other backends dropped stats that could not be deleted because
	 * somebody held references to it. If so, check this backend's references.
	 * This is not expected to happen often. The location of the check is a
	 * bit random, but this is a relatively frequently called path, so better
	 * than most.
	 */
	if (pgstat_custom_need_entry_refs_gc())
		pgstat_custom_gc_entry_refs();

	/*
	 * First check the lookup cache hashtable in local memory. If we find a
	 * match here we can avoid taking locks / causing contention.
	 */
	if (pgstat_custom_get_entry_ref_cached(key, &entry_ref))
		return entry_ref;

	Assert(entry_ref != NULL);

	/*
	 * Do a lookup in the hash table first - it's quite likely that the entry
	 * already exists, and that way we only need a shared lock.
	 */
	shhashent = dshash_find(pgStatCustomLocal.shared_hash, &key, false);

	if (create && !shhashent)
	{
		bool		shfound;

		/*
		 * It's possible that somebody created the entry since the above
		 * lookup. If so, fall through to the same path as if we'd have if it
		 * already had been created before the dshash_find() calls.
		 */
		shhashent = dshash_find_or_insert(pgStatCustomLocal.shared_hash, &key, &shfound);
		if (!shfound)
		{
			shheader = pgstat_custom_init_entry(kind, shhashent);
			if (shheader == NULL)
			{
				/*
				 * Failed the allocation of a new entry, so clean up the
				 * shared hashtable before giving up.
				 */
				dshash_delete_entry(pgStatCustomLocal.shared_hash, shhashent);

				ereport(ERROR,
						(errcode(ERRCODE_OUT_OF_MEMORY),
						 errmsg("out of memory"),
						 errdetail("Failed while allocating entry %u/%u/%u.",
								   key.kind, key.dboid, key.objoid)));
			}
			pgstat_custom_acquire_entry_ref(entry_ref, shhashent, shheader);

			if (created_entry != NULL)
				*created_entry = true;

			return entry_ref;
		}
	}

	if (!shhashent)
	{
		/*
		 * If we're not creating, delete the reference again. In all
		 * likelihood it's just a stats lookup - no point wasting memory for a
		 * shared ref to nothing...
		 */
		pgstat_custom_release_entry_ref(key, entry_ref, false);

		return NULL;
	}
	else
	{
		/*
		 * Can get here either because dshash_find() found a match, or if
		 * dshash_find_or_insert() found a concurrently inserted entry.
		 */

		if (shhashent->dropped && create)
		{
			/*
			 * There are legitimate cases where the old stats entry might not
			 * yet have been dropped by the time it's reused. The most obvious
			 * case are replication slot stats, where a new slot can be
			 * created with the same index just after dropping. But oid
			 * wraparound can lead to other cases as well. We just reset the
			 * stats to their plain state, while incrementing its "generation"
			 * in the shared entry for any remaining local references.
			 */
			shheader = pgstat_custom_reinit_entry(kind, shhashent);
			pgstat_custom_acquire_entry_ref(entry_ref, shhashent, shheader);

			if (created_entry != NULL)
				*created_entry = true;

			return entry_ref;
		}
		else if (shhashent->dropped)
		{
			dshash_release_lock(pgStatCustomLocal.shared_hash, shhashent);
			pgstat_custom_release_entry_ref(key, entry_ref, false);

			return NULL;
		}
		else
		{
			shheader = dsa_get_address(pgStatCustomLocal.dsa, shhashent->body);
			pgstat_custom_acquire_entry_ref(entry_ref, shhashent, shheader);

			return entry_ref;
		}
	}
}

static void
pgstat_custom_release_entry_ref(PgStat_HashKey key, PgStat_EntryRef *entry_ref,
						 bool discard_pending)
{
	if (entry_ref && entry_ref->pending)
	{
		if (discard_pending)
			pgstat_custom_delete_pending_entry(entry_ref);
		else
			elog(ERROR, "releasing ref with pending data");
	}

	if (entry_ref && entry_ref->shared_stats)
	{
		Assert(entry_ref->shared_stats->magic == 0xdeadbeef);
		Assert(entry_ref->pending == NULL);

		/*
		 * This can't race with another backend looking up the stats entry and
		 * increasing the refcount because it is not "legal" to create
		 * additional references to dropped entries.
		 */
		if (pg_atomic_fetch_sub_u32(&entry_ref->shared_entry->refcount, 1) == 1)
		{
			PgStatShared_HashEntry *shent;

			/*
			 * We're the last referrer to this entry, try to drop the shared
			 * entry.
			 */

			/* only dropped entries can reach a 0 refcount */
			Assert(entry_ref->shared_entry->dropped);

			shent = dshash_find(pgStatCustomLocal.shared_hash,
								&entry_ref->shared_entry->key,
								true);
			if (!shent)
				elog(ERROR, "could not find just referenced shared stats entry");

			/*
			 * This entry may have been reinitialized while trying to release
			 * it, so double-check that it has not been reused while holding a
			 * lock on its shared entry.
			 */
			if (pg_atomic_read_u32(&entry_ref->shared_entry->generation) ==
				entry_ref->generation)
			{
				/* Same "generation", so we're OK with the removal */
				Assert(pg_atomic_read_u32(&entry_ref->shared_entry->refcount) == 0);
				Assert(entry_ref->shared_entry == shent);
				pgstat_custom_free_entry(shent, NULL);
			}
			else
			{
				/*
				 * Shared stats entry has been reinitialized, so do not drop
				 * its shared entry, only release its lock.
				 */
				dshash_release_lock(pgStatCustomLocal.shared_hash, shent);
			}
		}
	}

	if (!pgstat_custom_entry_ref_hash_delete(pgStatCustomEntryRefHash, key))
		elog(ERROR, "entry ref vanished before deletion");

	if (entry_ref)
		pfree(entry_ref);
}

/*
 * Acquire exclusive lock on the entry.
 *
 * If nowait is true, it's just a conditional acquire, and the result
 * *must* be checked to verify success.
 * If nowait is false, waits as necessary, always returning true.
 */
bool
pgstat_custom_lock_entry(PgStat_EntryRef *entry_ref, bool nowait)
{
	LWLock	   *lock = &entry_ref->shared_stats->lock;

	if (nowait)
		return LWLockConditionalAcquire(lock, LW_EXCLUSIVE);

	LWLockAcquire(lock, LW_EXCLUSIVE);
	return true;
}

/*
 * Acquire shared lock on the entry.
 *
 * Separate from pgstat_lock_entry() as most callers will need to lock
 * exclusively.  The wait semantics are identical.
 */
bool
pgstat_custom_lock_entry_shared(PgStat_EntryRef *entry_ref, bool nowait)
{
	LWLock	   *lock = &entry_ref->shared_stats->lock;

	if (nowait)
		return LWLockConditionalAcquire(lock, LW_SHARED);

	LWLockAcquire(lock, LW_SHARED);
	return true;
}

void
pgstat_custom_unlock_entry(PgStat_EntryRef *entry_ref)
{
	LWLockRelease(&entry_ref->shared_stats->lock);
}

void
pgstat_custom_request_entry_refs_gc(void)
{
	pg_atomic_fetch_add_u64(&pgStatCustomLocal.shmem->gc_request_count, 1);
}

static bool
pgstat_custom_need_entry_refs_gc(void)
{
	uint64		curage;

	if (!pgStatCustomEntryRefHash)
		return false;

	/* should have been initialized when creating pgStatCustomEntryRefHash */
	Assert(pgStatCustomSharedRefAge != 0);

	curage = pg_atomic_read_u64(&pgStatCustomLocal.shmem->gc_request_count);

	return pgStatCustomSharedRefAge != curage;
}

static void
pgstat_custom_gc_entry_refs(void)
{
	pgstat_custom_entry_ref_hash_iterator i;
	PgStat_EntryRefHashEntry *ent;
	uint64		curage;

	curage = pg_atomic_read_u64(&pgStatCustomLocal.shmem->gc_request_count);
	Assert(curage != 0);

	/*
	 * Some entries have been dropped or reinitialized.  Invalidate cache
	 * pointer to them.
	 */
	pgstat_custom_entry_ref_hash_start_iterate(pgStatCustomEntryRefHash, &i);
	while ((ent = pgstat_custom_entry_ref_hash_iterate(pgStatCustomEntryRefHash, &i)) != NULL)
	{
		PgStat_EntryRef *entry_ref = ent->entry_ref;

		Assert(!entry_ref->shared_stats ||
			   entry_ref->shared_stats->magic == 0xdeadbeef);

		/*
		 * "generation" checks for the case of entries being reinitialized,
		 * and "dropped" for the case where these are..  dropped.
		 */
		if (!entry_ref->shared_entry->dropped &&
			pg_atomic_read_u32(&entry_ref->shared_entry->generation) ==
			entry_ref->generation)
			continue;

		/* cannot gc shared ref that has pending data */
		if (entry_ref->pending != NULL)
			continue;

		pgstat_custom_release_entry_ref(ent->key, entry_ref, false);
	}

	pgStatCustomSharedRefAge = curage;
}

static void
pgstat_custom_release_matching_entry_refs(bool discard_pending, ReleaseMatchCB match,
								   Datum match_data)
{
	pgstat_custom_entry_ref_hash_iterator i;
	PgStat_EntryRefHashEntry *ent;

	if (pgStatCustomEntryRefHash == NULL)
		return;

	pgstat_custom_entry_ref_hash_start_iterate(pgStatCustomEntryRefHash, &i);

	while ((ent = pgstat_custom_entry_ref_hash_iterate(pgStatCustomEntryRefHash, &i))
		   != NULL)
	{
		Assert(ent->entry_ref != NULL);

		if (match && !match(ent, match_data))
			continue;

		pgstat_custom_release_entry_ref(ent->key, ent->entry_ref, discard_pending);
	}
}

/*
 * Release all local references to shared stats entries.
 *
 * When a process exits it cannot do so while still holding references onto
 * stats entries, otherwise the shared stats entries could never be freed.
 */
static void
pgstat_custom_release_all_entry_refs(bool discard_pending)
{
	if (pgStatCustomEntryRefHash == NULL)
		return;

	pgstat_custom_release_matching_entry_refs(discard_pending, NULL, 0);
	Assert(pgStatCustomEntryRefHash->members == 0);
	pgstat_custom_entry_ref_hash_destroy(pgStatCustomEntryRefHash);
	pgStatCustomEntryRefHash = NULL;
}

static bool
match_db(PgStat_EntryRefHashEntry *ent, Datum match_data)
{
	Oid			dboid = DatumGetObjectId(match_data);

	return ent->key.dboid == dboid;
}

static void
pgstat_custom_release_db_entry_refs(Oid dboid)
{
	pgstat_custom_release_matching_entry_refs( /* discard pending = */ true,
									   match_db,
									   ObjectIdGetDatum(dboid));
}

/*
 * Helper for both pgstat_drop_database_and_contents() and
 * pgstat_drop_entry(). If hstat is non-null delete the shared entry using
 * dshash_delete_current(), otherwise use dshash_delete_entry(). In either
 * case the entry needs to be already locked.
 */
static bool
pgstat_custom_drop_entry_internal(PgStatShared_HashEntry *shent,
						   dshash_seq_status *hstat)
{
	Assert(shent->body != InvalidDsaPointer);

	/* should already have released local reference */
	if (pgStatCustomEntryRefHash)
		Assert(!pgstat_custom_entry_ref_hash_lookup(pgStatCustomEntryRefHash, shent->key));

	/*
	 * Signal that the entry is dropped - this will eventually cause other
	 * backends to release their references.
	 */
	if (shent->dropped)
		elog(ERROR,
			 "trying to drop stats entry already dropped: kind=%s dboid=%u objid=%u refcount=%u generation=%u",
			 pgstat_get_kind_info(shent->key.kind)->name,
			 shent->key.dboid,
			 shent->key.objoid,
			 pg_atomic_read_u32(&shent->refcount),
			 pg_atomic_read_u32(&shent->generation));
	shent->dropped = true;

	/* release refcount marking entry as not dropped */
	if (pg_atomic_sub_fetch_u32(&shent->refcount, 1) == 0)
	{
		pgstat_custom_free_entry(shent, hstat);
		return true;
	}
	else
	{
		if (!hstat)
			dshash_release_lock(pgStatCustomLocal.shared_hash, shent);
		return false;
	}
}

/*
 * Drop stats for the database and all the objects inside that database.
 */
static void
pgstat_custom_drop_database_and_contents(Oid dboid)
{
	dshash_seq_status hstat;
	PgStatShared_HashEntry *p;
	uint64		not_freed_count = 0;

	Assert(OidIsValid(dboid));

	Assert(pgStatCustomLocal.shared_hash != NULL);

	/*
	 * This backend might very well be the only backend holding a reference to
	 * about-to-be-dropped entries. Ensure that we're not preventing it from
	 * being cleaned up till later.
	 *
	 * Doing this separately from the dshash iteration below avoids having to
	 * do so while holding a partition lock on the shared hashtable.
	 */
	pgstat_custom_release_db_entry_refs(dboid);

	/* some of the dshash entries are to be removed, take exclusive lock. */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, true);
	while ((p = dshash_seq_next(&hstat)) != NULL)
	{
		if (p->dropped)
			continue;

		if (p->key.dboid != dboid)
			continue;

		if (!pgstat_custom_drop_entry_internal(p, &hstat))
		{
			/*
			 * Even statistics for a dropped database might currently be
			 * accessed (consider e.g. database stats for pg_stat_database).
			 */
			not_freed_count++;
		}
	}
	dshash_seq_term(&hstat);

	/*
	 * If some of the stats data could not be freed, signal the reference
	 * holders to run garbage collection of their cached pgStatShmLookupCache.
	 */
	if (not_freed_count > 0)
		pgstat_request_entry_refs_gc();
}

/*
 * Drop a single stats entry.
 *
 * This routine returns false if the stats entry of the dropped object could
 * not be freed, true otherwise.
 *
 * The callers of this function should call pgstat_request_entry_refs_gc()
 * if the stats entry could not be freed, to ensure that this entry's memory
 * can be reclaimed later by a different backend calling
 * pgstat_custom_gc_entry_refs().
 */
bool
pgstat_custom_drop_entry(PgStat_Kind kind, Oid dboid, Oid objid)
{
	PgStat_HashKey key;
	PgStatShared_HashEntry *shent;
	bool		freed = true;

	/* clear padding */
	memset(&key, 0, sizeof(struct PgStat_HashKey));

	key.kind = kind;
	key.dboid = dboid;
	key.objoid = objid;

	/* delete local reference */
	if (pgStatCustomEntryRefHash)
	{
		PgStat_EntryRefHashEntry *lohashent =
			pgstat_custom_entry_ref_hash_lookup(pgStatCustomEntryRefHash, key);

		if (lohashent)
			pgstat_custom_release_entry_ref(lohashent->key, lohashent->entry_ref,
									 true);
	}

	/* mark entry in shared hashtable as deleted, drop if possible */
	shent = dshash_find(pgStatCustomLocal.shared_hash, &key, true);
	if (shent)
	{
		freed = pgstat_custom_drop_entry_internal(shent, NULL);

		/*
		 * Database stats contain other stats. Drop those as well when
		 * dropping the database. XXX: Perhaps this should be done in a
		 * slightly more principled way? But not obvious what that'd look
		 * like, and so far this is the only case...
		 */
		if (key.kind == PGSTAT_KIND_DATABASE)
			pgstat_custom_drop_database_and_contents(key.dboid);
	}

	return freed;
}


/*
 * Scan through the shared hashtable of stats, dropping statistics if
 * approved by the optional do_drop() function.
 */
void
pgstat_custom_drop_matching_entries(bool (*do_drop) (PgStatShared_HashEntry *, Datum),
							 Datum match_data)
{
	dshash_seq_status hstat;
	PgStatShared_HashEntry *ps;
	uint64		not_freed_count = 0;

	/* entries are removed, take an exclusive lock */
	dshash_seq_init(&hstat, pgStatCustomLocal.shared_hash, true);
	while ((ps = dshash_seq_next(&hstat)) != NULL)
	{
		if (ps->dropped)
			continue;

		if (do_drop != NULL && !do_drop(ps, match_data))
			continue;

		/* delete local reference */
		if (pgStatCustomEntryRefHash)
		{
			PgStat_EntryRefHashEntry *lohashent =
				pgstat_custom_entry_ref_hash_lookup(pgStatCustomEntryRefHash, ps->key);

			if (lohashent)
				pgstat_custom_release_entry_ref(lohashent->key, lohashent->entry_ref,
										 true);
		}

		if (!pgstat_custom_drop_entry_internal(ps, &hstat))
			not_freed_count++;
	}
	dshash_seq_term(&hstat);

	if (not_freed_count > 0)
		pgstat_custom_request_entry_refs_gc();
}

/* ------------------------------------------------------------
 * Dropping and resetting of stats entries
 * ------------------------------------------------------------
 */

static void
pgstat_custom_free_entry(PgStatShared_HashEntry *shent, dshash_seq_status *hstat)
{
	dsa_pointer pdsa;

	/*
	 * Fetch dsa pointer before deleting entry - that way we can free the
	 * memory after releasing the lock.
	 */
	pdsa = shent->body;

	if (!hstat)
		dshash_delete_entry(pgStatCustomLocal.shared_hash, shent);
	else
		dshash_delete_current(hstat);

	dsa_free(pgStatCustomLocal.dsa, pdsa);
}

static void
pgstat_custom_setup_memcxt(void)
{
	if (unlikely(!pgStatCustomSharedRefContext))
		pgStatCustomSharedRefContext =
			AllocSetContextCreate(TopMemoryContext,
								  "PgStat Custom Shared Ref",
								  ALLOCSET_SMALL_SIZES);
	if (unlikely(!pgStatCustomEntryRefHashContext))
		pgStatCustomEntryRefHashContext =
			AllocSetContextCreate(TopMemoryContext,
								  "PgStat Custom Shared Ref Hash",
								  ALLOCSET_SMALL_SIZES);
}

#endif
