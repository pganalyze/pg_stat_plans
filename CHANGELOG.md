# Changelog

## Unreleased

* Postgres 20 support (in development, tested against the master branch)
  - Add plan jumble funcs for Postgres 20
  - Adapt to per-kind stats hash tables and DSA areas in pgstats
  - Store plan entries in a dedicated stats hash table, separate from the
    shared hash table used by other stats kinds
  - Adapt to pg_attribute_always_inline being removed in favor of pg_always_inline
* Don't associate plan entries with their database in the stats system
  - Fixes pg_stat_reset() clearing the plan entries of the current database
    in place, which lost their plan text, user and query/plan IDs, and leaked
    the memory used by the plan text
  - Plans of a dropped database are now kept until they are deallocated or
    reset, like in pg_stat_statements, instead of being dropped together with
    the database
* Postgres 16/17 compatibility layer
  - Fix crash in processes that are not regular client backends (#31)
    - The stats machinery was only attached in the client authentication
      hook, which background workers, parallel workers, autovacuum workers
      and single-user mode never run. Any such process that ran a tracked
      query, or read pg_stat_plans, crashed the server. Instead, attach
      on first use.
  - Fix request of shared memory used for the stats hash table
  - Fix invalid memory access when reporting a double drop of a stats entry
  - Fix crashes after a failed stats entry allocation
    - Ports the upstream fixes for a partially initialized entry being left
      behind when shared memory allocation fails, both in the backend-local
      reference cache
      ([4069df21be](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=4069df21beb838e75e8639c47e6a9c800e3c8af5),
      [fc29deb521](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=fc29deb52106e710e9eba4d0f59ee185c8d200bf))
      and in the shared hash table
      ([d9de60c5e4](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=d9de60c5e47a7f7a5dcee050d119bda08ea85d55))
  - Fix cleanup of stats entries that were reused and dropped again while
    another backend still held a reference
    - Ports the upstream fix to pgstat_release_entry_ref
      ([e9d0600aba](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=e9d0600aba5467b352eb67aaf6ad92a9a4776b0a))

## 2.1.1   2026-09-23

* Remove experimental marker
  - The design has been sufficiently reviewed and aligns with the direction
    of pg_stat_statements, and additional stress testing has been done on
    concurrency and scaling issues
* Postgres 19: Pass missing_ok=true for pgstat_drop_entry
  - Stats entries can get dropped outside of the extension's control, e.g.
    when a database is dropped. This avoids errors when attempting to drop
    an already dropped stats entry.
* Postgres 19: Update jumble funcs for Postgres 19 beta 4
* Fix compiler warnings


## 2.1.0   2026-06-05

* Postgres 19 support
* Optionally capture plan advice string on Postgres 19
  - When enabled with the new pg_stat_plans.plan_advice setting, plan advice
    will be tracked during each query's planning cycle, and the generated
    advice will be stored in shared memory for the first execution of a given
    plan ID. This is similar to running EXPLAIN (PLAN_ADVICE) on the query
    and helps determine the advice strings that can reproduce a given plan.
* Add pg_stat_plans.max_plan_memory setting to total plan text memory
  - Previously the limit was implicitly calculated from the max * max_size,
    but plan text sizes can be quite uneven, and its easier to reason about
    a fixed limit. Together with this change, rework how the plan text limit
    is implemented, by relying on dsa_set_size_limit.
  - The new default limit is 16MB, up from the prior implicit 10MB. Due to
    max_size now being uncoupled from the actual limit, also raise the default
    max_size to 8kb of (potentially compressed) plan text. This default is
    chosen to optimize for the DSA handling of "smaller entries" that avoids
    allocating full DSA pages. Entries that go over the limit will have a
    blank value for plan text.
* Correctness/scaling improvements
  - Use pending statistics correctly to fix data race
  - Prevent concurrent garbage collection cycles
  - Eagerly free plan text when dropping entries to support resurrection
* Maintenance improvements
  - Regenerate jumble funcs from Postgres sources using script
  - Avoid unused warning for _jumblElements, drop RecordConstLocation
  -  Fix compiler warnings
  - Fix regression tests for Postgres 16+17, move pgstat_custom for clarity


## 2.0.0   2025-09-11

* Initial release

