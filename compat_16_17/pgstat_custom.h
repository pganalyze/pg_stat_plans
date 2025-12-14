#ifndef PGSTAT_CUSTOM_H
#define PGSTAT_CUSTOM_H

#include "utils/pgstat_internal.h"

#if PG_VERSION_NUM >= 180000

/* Alias built-in stats functions, since we can rely on them to support custom stats */

#define pgStatCustomLocal pgStatLocal

#define pgstat_custom_lock_entry pgstat_lock_entry
#define pgstat_custom_unlock_entry pgstat_unlock_entry
#define pgstat_custom_drop_entry pgstat_drop_entry
#define pgstat_custom_drop_matching_entries pgstat_drop_matching_entries
#define pgstat_custom_request_entry_refs_gc pgstat_request_entry_refs_gc

#define pgstat_custom_get_entry_data pgstat_get_entry_data


#define pgstat_custom_get_kind_info pgstat_get_kind_info
#define pgstat_custom_register_kind pgstat_register_kind
#define pgstat_custom_prep_pending_entry pgstat_prep_pending_entry

#define pgstat_custom_drop_matching_entries pgstat_drop_matching_entries

#else

extern PGDLLIMPORT PgStat_LocalState pgStatCustomLocal;

#ifdef USE_ASSERT_CHECKING
extern void pgstat_custom_assert_is_up(void);
#else
#define pgstat_custom_assert_is_up() ((void)true)
#endif

extern void pgstat_custom_initialize(void);
extern void StatsCustomShmemInit(void);
extern void pgstat_custom_attach_shmem(void);
extern void pgstat_custom_detach_shmem(void);
extern long pgstat_custom_report_stat(bool force);

extern const PgStat_KindInfo *pgstat_custom_get_kind_info(PgStat_Kind kind);
extern void pgstat_custom_register_kind(PgStat_Kind kind, const PgStat_KindInfo *kind_info);
extern void pgstat_custom_delete_pending_entry(PgStat_EntryRef *entry_ref);
extern PgStat_EntryRef *pgstat_custom_prep_pending_entry(PgStat_Kind kind, Oid dboid, Oid objid, bool *created_entry);
extern PgStat_EntryRef *pgstat_custom_fetch_pending_entry(PgStat_Kind kind, Oid dboid, Oid objid);

extern PgStat_EntryRef * pgstat_custom_get_entry_ref(PgStat_Kind kind, Oid dboid, Oid objid, bool create, bool *created_entry);

extern bool pgstat_custom_lock_entry(PgStat_EntryRef *entry_ref, bool nowait);
extern bool pgstat_custom_lock_entry_shared(PgStat_EntryRef *entry_ref, bool nowait);
extern void pgstat_custom_unlock_entry(PgStat_EntryRef *entry_ref);
extern bool pgstat_custom_drop_entry(PgStat_Kind kind, Oid dboid, Oid objoid);
extern void pgstat_custom_drop_matching_entries(bool (*do_drop) (PgStatShared_HashEntry *, Datum), Datum match_data);
extern void pgstat_custom_request_entry_refs_gc(void);

static inline void *pgstat_custom_get_entry_data(PgStat_Kind kind, PgStatShared_Common *entry);


/*
 * The length of the data portion of a shared memory stats entry (i.e. without
 * transient data such as refcounts, lwlocks, ...).
 */
static inline size_t
pgstat_custom_get_entry_len(PgStat_Kind kind)
{
	return pgstat_custom_get_kind_info(kind)->shared_data_len;
}

/*
 * Returns a pointer to the data portion of a shared memory stats entry.
 */
static inline void *
pgstat_custom_get_entry_data(PgStat_Kind kind, PgStatShared_Common *entry)
{
	size_t		off = pgstat_custom_get_kind_info(kind)->shared_data_off;

	Assert(off != 0 && off < PG_UINT32_MAX);

	return ((char *) (entry)) + off;
}

#endif


#endif							/* PGSTAT_CUSTOM_H */
