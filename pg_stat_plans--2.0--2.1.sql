/* contrib/pg_stat_plans/pg_stat_plans--2.0--2.1.sql */

-- complain if script is sourced in psql, rather than via ALTER EXTENSION
\echo Use "ALTER EXTENSION pg_stat_plans UPDATE TO '2.1'" to load this file. \quit

-- Adding the plan_advice output column changes the result type of
-- pg_stat_plans(boolean), so the dependent views and the function must be
-- dropped and recreated.
DROP VIEW pg_stat_plans_activity;
DROP VIEW pg_stat_plans;
DROP FUNCTION pg_stat_plans(boolean);

CREATE FUNCTION pg_stat_plans(IN showplan boolean,
    OUT userid oid,
    OUT dbid oid,
    OUT toplevel bool,
    OUT queryid int8,
    OUT planid int8,
    OUT calls int8,
    OUT total_exec_time float8,
    OUT plan text,
    OUT plan_advice text
)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'pg_stat_plans_2_0'
LANGUAGE C STRICT VOLATILE PARALLEL SAFE;

CREATE VIEW pg_stat_plans AS
  SELECT * FROM pg_stat_plans(true);

GRANT SELECT ON pg_stat_plans TO PUBLIC;

CREATE VIEW pg_stat_plans_activity AS
  SELECT a.pid, a.plan_id, p.plan, p.plan_advice
    FROM pg_stat_plans_get_activity(NULL) a
    JOIN pg_stat_plans(true) p
         ON (a.datid = p.dbid AND a.usesysid = p.userid AND a.query_id = p.queryid AND a.plan_id = p.planid AND p.toplevel IS TRUE);

GRANT SELECT ON pg_stat_plans_activity TO PUBLIC;
