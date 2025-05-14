/* contrib/pg_stat_plans/pg_stat_plans--2.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_stat_plans" to load this file. \quit

-- Register functions.
CREATE FUNCTION pg_stat_plans_reset()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C PARALLEL SAFE;

CREATE FUNCTION pg_stat_plans(IN showplan boolean,
    OUT userid oid,
    OUT dbid oid,
    OUT toplevel bool,
    OUT queryid int8,
    OUT planid int8,
    OUT calls int8,
    OUT total_exec_time float8,
    OUT plan text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_stat_plans_2_0'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE FUNCTION pg_stat_plans_get_activity(IN pid int4,
    OUT datid oid,
    OUT pid int4,
    OUT usesysid oid,
    OUT query_id int8,
    OUT plan_id int8
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_stat_plans_2_0_get_activity'
LANGUAGE C PARALLEL RESTRICTED;

-- Register a view on the functions for ease of use.
CREATE VIEW pg_stat_plans AS
  SELECT * FROM pg_stat_plans(true);

GRANT SELECT ON pg_stat_plans TO PUBLIC;

CREATE VIEW pg_stat_plans_activity AS
  SELECT a.pid, a.plan_id, p.plan
    FROM pg_stat_plans_get_activity(NULL) a
    JOIN pg_stat_plans(true) p
         ON (a.datid = p.dbid AND a.usesysid = p.userid AND a.query_id = p.queryid AND a.plan_id = p.planid AND p.toplevel IS TRUE);

GRANT SELECT ON pg_stat_plans_activity TO PUBLIC;

-- Don't want reset to be available to non-superusers, matching pg_stat_statements permissions.
REVOKE ALL ON FUNCTION pg_stat_plans_reset() FROM PUBLIC;
