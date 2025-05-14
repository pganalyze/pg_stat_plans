# pg_stat_plans 2.0 - Track per-plan call counts, execution times and EXPLAIN texts in Postgres

`pg_stat_plans` is designed for low overhead tracking of aggregate plan statistics in Postgres, by relying on hashing the plan tree with a plan ID calculation. It aims to help identify plan regressions, and get an example plan for each Postgres query run, slow and fast. Additionally, it allows showing the plan for a currently running query.

Plan texts are stored in shared memory for efficiency reasons (instead of a local file), with support for `zstd` compression to compress large plan texts.

Plans have the same plan IDs when they have the same "plan shape", which intends to match `EXPLAIN (COSTS OFF)`. This extension is optimized for tracking changes in plan shape, but does not aim to track execution statistics for plans, like [auto_explain](https://www.postgresql.org/docs/current/auto-explain.html) can do for outliers.

This project is inspired by multiple Postgres community projects, including the original [pg_stat_plans](https://github.com/2ndQuadrant/pg_stat_plans) extension (unmaintained), with a goal of upstreaming parts of this extension into the core Postgres project over time.

**Experimental**. May still change in incompatible ways without notice. Not (yet) recommended for production use.

## Supported PostgreSQL versions

Currently requires Postgres 18 beta1, due to relying on pluggable cumulative statistics ([7949d95945](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=7949d9594582ab49dee221e1db1aa5401ace49d4)) and plan ID tracking per backend ([2a0cd38da5](https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=2a0cd38da5ccf70461c51a489ee7d25fcd3f26be)). 

Support for older versions with a reduced feature set will likely be added in the future.

## Installation

You can use `make install` to build and install the extension. This requires having a `pg_config` in your path that references a Postgres 18 beta1 or newer installation. You can optionally build with `zstd` support for compressing plan texts in shared memory.

After installing, make sure that your Postgres server loads the shared library:

```
shared_preload_libraries = 'pg_stat_plans'

# Optionally, enable zstd compression for plan texts
pg_stat_plans.compress = 'zstd'
```

Whilst `pg_stat_statements` is not directly required to use `pg_stat_plans`, you will likely want that in practice to make effective use of this extension.

## Usage

Once enabled, the `pg_stat_plans` extension will track cumulative plan statistics on all databases on your Postgres database server.

In order to query the collected plan statistics, access the `pg_stat_plans` view:

```sql
SELECT * FROM pg_stat_plans;
```
```
-[ RECORD 1 ]---+----------------------------------------------------------------------------------------------------------------------------
userid          | 10
dbid            | 16391
toplevel        | t
queryid         | -2322344003805516737
planid          | -1865871893278385236
calls           | 1
total_exec_time | 0.047708
plan            | Limit                                                                                                                      +
                |   ->  Sort                                                                                                                 +
                |         Sort Key: database_stats_35d.frozenxid_age DESC                                                                    +
                |         ->  Bitmap Heap Scan on database_stats_35d_20250514 database_stats_35d                                             +
                |               Recheck Cond: (server_id = '00000000-0000-0000-0000-000000000000'::uuid)                                     +
                |               Filter: ((frozenxid_age IS NOT NULL) AND (collected_at = '2025-05-14 14:30:00'::timestamp without time zone))+
                |               ->  Bitmap Index Scan on database_stats_35d_20250514_server_id_idx                                           +
                |                     Index Cond: (server_id = '00000000-0000-0000-0000-000000000000'::uuid)
```

If you are only interested in the statistics, you can alternatively call `pg_stat_plans(false)` to omit the plan text:

```sql
SELECT * FROM pg_stat_plans(false);
```
```
 userid | dbid  | toplevel |       queryid        |        planid        | calls | total_exec_time | plan 
--------+-------+----------+----------------------+----------------------+-------+-----------------+------
     10 | 16391 | t        | -5621848818004107520 |  6961434712743557023 |     1 |        0.039874 | 
     10 | 16391 | t        | -2441310672058481123 | -2196946116021194031 |     1 |        0.137792 | 
     10 | 16391 | t        | -6930725455674591191 | -2072755433191687359 |     1 |        0.199792 | 
 426625 |     5 | t        | -8648076524241661623 |  3162221630963173795 |     2 |        2.409084 | 
 426625 |     5 | t        |  8478736882705947225 |   -45743379005492998 |     3 |        7.022666 | 
(5 rows)
```

You can also group by `queryid` retrieved from `pg_stat_statements`, to get the different plans chosen for the same query. For example, we can see different plans being chosen based on whether a table was expected to have data or not, and Postgres falling back to a sequential scan and in efficient Hash Join incorrectly:

```sql
SELECT queryid, query FROM pg_stat_statements WHERE queryid = -7079927730720784986;
```
-[ RECORD 1 ]-------------------------------------------------------------------------------------------------------------------------
queryid | -7079927730720784986
query   | INSERT INTO schema_column_stats_7d (                                                                                        +
        |         database_id, table_id, analyzed_at, position, inherited, null_frac, avg_width, n_distinct, correlation              +
        |     )                                                                                                                       +
        |     ...                                                                                                                     +
        |     WHERE NOT EXISTS (                                                                                                      +
        |         SELECT $12 FROM schema_column_stats_7d s                                                                            +
        |         WHERE (s.table_id, s.analyzed_at) = (input.table_id, greatest(input.analyzed_at, date_trunc($13, $10::timestamptz)))+
        |     )
```
```sql
SELECT planid, calls, total_exec_time / calls avgtime, plan FROM pg_stat_plans WHERE queryid = -7079927730720784986;
```
```
-[ RECORD 1 ]---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
planid  | 7066245182124090635
calls   | 4
avgtime | 0.010312250000000002
plan    | Insert on schema_column_stats_7d                                                                                                                                                          +
        |   ->  Nested Loop Anti Join                                                                                                                                                               +
        |         ->  Function Scan on input                                                                                                                                                        +
        |         ->  Append                                                                                                                                                                        +
        |               ->  Index Only Scan using schema_column_stats_7d_20250505_pkey on schema_column_stats_7d_20250505 s_6                                                                       +
        |                     Index Cond: ((table_id = input.table_id) AND (analyzed_at = GREATEST(input.analyzed_at, date_trunc('day'::text, '2025-05-07 14:30:00+00'::timestamp with time zone))))+
        |               ->  Index Only Scan using schema_column_stats_7d_20250506_pkey on schema_column_stats_7d_20250506 s_7                                                                       +
        |                     Index Cond: ((table_id = input.table_id) AND (analyzed_at = GREATEST(input.analyzed_at, date_trunc('day'::text, '2025-05-07 14:30:00+00'::timestamp with time zone))))+
        |               ->  Index Only Scan using schema_column_stats_7d_20250507_pkey on schema_column_stats_7d_20250507 s_8                                                                       +
        |                     Index Cond: ((table_id = input.table_id) AND (analyzed_at = GREATEST(input.analyzed_at, date_trunc('day'::text, '2025-05-07 14:30:00+00'::timestamp with time zone))))+
-[ RECORD 2 ]---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
planid  | 6144932094104289715
calls   | 2
avgtime | 18.104062499999998
plan    | Insert on schema_column_stats_7d                                                                                                                                                          +
        |   ->  Hash Anti Join                                                                                                                                                                      +
        |         Hash Cond: (input.table_id = s.table_id)                                                                                                                                          +
        |         Join Filter: (s.analyzed_at = GREATEST(input.analyzed_at, date_trunc('day'::text, '2025-05-07 14:30:00+00'::timestamp with time zone)))                                           +
        |         ->  Function Scan on input                                                                                                                                                        +
        |         ->  Hash                                                                                                                                                                          +
        |               ->  Append                                                                                                                                                                  +
        |                     ->  Index Only Scan using schema_column_stats_7d_20250505_pkey on schema_column_stats_7d_20250505 s_6                                                                 +
        |                     ->  Seq Scan on schema_column_stats_7d_20250506 s_7                                                                                                                   +
        |                     ->  Seq Scan on schema_column_stats_7d_20250507 s_8                                                                                                                   +
```

Plans will be shown for both currently running queries, as well as those that have finished execution. The call count is updated after execution ends.

You can reset all plan statistics and texts by running `pg_stat_plan_reset`:

```sql
SELECT pg_stat_plans_reset();
```

On Postgres 18 and newer, you can retrieve the plan ID and plans for currently running queries through the `pg_stat_plans_activity` view:

```sql
SELECT * FROM pg_stat_plans_activity;
```
```
  pid  |       plan_id        |                                                          plan                                                          
-------+----------------------+------------------------------------------------------------------------------------------------------------------------
 83994 | -5449095327982245076 | Merge Join                                                                                                            +
       |                      |   Merge Cond: ((a.datid = p.dbid) AND (a.usesysid = p.userid) AND (a.query_id = p.queryid) AND (a.plan_id = p.planid))+
       |                      |   ->  Sort                                                                                                            +
       |                      |         Sort Key: a.datid, a.usesysid, a.query_id, a.plan_id                                                          +
       |                      |         ->  Function Scan on pg_stat_plans_get_activity a                                                             +
       |                      |   ->  Sort                                                                                                            +
       |                      |         Sort Key: p.dbid, p.userid, p.queryid, p.planid                                                               +
       |                      |         ->  Function Scan on pg_stat_plans p                                                                          +
       |                      |               Filter: (toplevel IS TRUE)
 87168 |  4721228144609632390 | Sort                                                                                                                  +
       |                      |   Sort Key: q.id                                                                                                      +
       |                      |   ->  Nested Loop                                                                                                     +
       |                      |         ->  Index Scan using index_query_runs_on_server_id on query_runs q                                            +
       |                      |               Index Cond: (server_id = '00000000-0000-0000-0000-000000000000'::uuid)                                  +
       |                      |               Filter: ((started_at IS NULL) AND (finished_at IS NULL))                                                +
       |                      |         ->  Index Scan using databases_pkey on databases db                                                           +
       |                      |               Index Cond: (id = q.database_id)
 81527 |  3819832514333472635 | Result
(3 rows)
```

## Running tests

You can use `make installcheck` to run the regression tests.

Note that these will run against an existing local Postgres installation, which must have `pg_stat_plans` in its `shared_preload_libaries`.

## Configuration

| setting                | possible values | default | description                                                                               |   |   |
|------------------------|-----------------|---------|-------------------------------------------------------------------------------------------|---|---|
| pg_stat_plans.max      | 100 - INT_MAX/2 | 5000    | Sets the maximum number of plans tracked by pg_stat_plans in shared memory.               |   |   |
| pg_stat_plans.max_size | 100 - 1048576   | 2048    | Sets the maximum size of plan texts (in bytes) tracked by pg_stat_plans in shared memory. |   |   |
| pg_stat_plans.track    | top<br>all         | top     | Selects which plans are tracked by pg_stat_plans.                                         |   |   |
| pg_stat_plans.compress | none<br>zstd       | none    | Select compression used by pg_stat_plans.                                                 |   |   |

## Known issues

* Plan IDs may be different in cases where they should not be
  - Minor differences in filter / index cond expressions (e.g. an extra type cast)
  - Different partitions being planned for the same Append/Append Merge node based on changes in schema or input parameters
* Plan text compression may have higher CPU overhead than necessary
  - Plan text is always compressed (if setting is enabled), but this likely needs a minimum threshold to reduce overhead
  - Explore/benchmark alternate compression methods (e.g. lz4 for lower CPU overhead)


## Authors

* Lukas Fittl
* Marko M.

Inspired by earlier work done by Sami Imseih.

## License

PostgreSQL server code (jumblefuncs.*) incorporated under the PostgreSQL license
Portions Copyright (c) 1996-2025, The PostgreSQL Global Development Group
Portions Copyright (c) 1994, The Regents of the University of California

All other parts are licensed under the PostgreSQL license
Copyright (c) 2025, Duboce Labs, Inc. (pganalyze) <team@pganalyze.com>

See LICENSE file for details.
