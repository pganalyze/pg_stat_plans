--
-- pg_plan_advice string collection (Postgres 19+ only)
--
-- This test is only run when pg_plan_advice is available and preloaded
-- alongside pg_stat_plans (see the Makefile). The extension was already
-- created by the "select" test.
--

-- Disable parallelism so the chosen plans (and thus the generated advice)
-- are deterministic.
SET max_parallel_workers_per_gather = 0;

CREATE TABLE pa_t1(id int primary key, x int);
CREATE TABLE pa_t2(id int primary key, t1_id int);
INSERT INTO pa_t1 SELECT g, g FROM generate_series(1, 1000) g;
INSERT INTO pa_t2 SELECT g, g % 1000 + 1 FROM generate_series(1, 5000) g;
ANALYZE pa_t1, pa_t2;

--
-- off: advice is never collected, even on repeated execution
--
SET pg_stat_plans.plan_advice = off;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SELECT count(*) FROM pa_t1 WHERE x < 100;
SELECT count(*) FROM pa_t1 WHERE x < 100;
SELECT plan_advice IS NULL AS advice_is_null
  FROM pg_stat_plans WHERE plan LIKE '%pa_t1%' AND plan NOT LIKE '%pg_stat_plans%';

--
-- on: advice is collected on the first execution
--
SET pg_stat_plans.plan_advice = on;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SELECT count(*) FROM pa_t1 WHERE x < 100;
SELECT plan_advice IS NOT NULL AS advice_present
  FROM pg_stat_plans WHERE plan LIKE '%pa_t1%' AND plan NOT LIKE '%pg_stat_plans%';

DROP TABLE pa_t1, pa_t2;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
