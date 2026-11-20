--
-- Running alongside pg_stat_statements.
--
-- In this test run, pg_stat_statements is preloaded before pg_stat_plans, so
-- our hooks run first, and its hooks see the statement as we leave it. In
-- particular, the query ID of a utility statement has to survive our
-- ProcessUtility hook: pg_stat_statements skips statements with a query ID
-- of zero, so clearing it there made it lose every utility statement.
--

CREATE EXTENSION pg_stat_statements;
SET pg_stat_statements.track_utility = on;

SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SELECT pg_stat_statements_reset() IS NOT NULL AS t;

CREATE TABLE pgss_utility (id int);
COPY pgss_utility TO STDOUT;
VACUUM pgss_utility;
CREATE INDEX pgss_utility_idx ON pgss_utility (id);
EXPLAIN (COSTS OFF) SELECT * FROM pgss_utility;

-- PREPARE and EXECUTE go through ProcessUtility as well, but the execution of
-- the prepared statement is tracked by the executor hooks of both extensions.
PREPARE pgss_prep AS SELECT count(*) FROM pgss_utility;
EXECUTE pgss_prep;
DEALLOCATE pgss_prep;

-- Wait for pending stats to be flushed
SELECT pg_sleep(1);

-- pg_stat_statements tracked the utility statements, and the prepared
-- statement under the text of its PREPARE
SELECT calls, query FROM pg_stat_statements
  WHERE query ~ '^(COPY|VACUUM|CREATE INDEX|EXPLAIN|PREPARE)'
  ORDER BY query COLLATE "C";

-- pg_stat_plans only tracked the plan of the prepared statement
SELECT calls, plan FROM pg_stat_plans
  WHERE plan LIKE '%pgss_utility%'
    AND plan NOT LIKE '%Function Scan on pg_stat_plans%'
  ORDER BY plan COLLATE "C";

DROP TABLE pgss_utility;
DROP EXTENSION pg_stat_statements;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
