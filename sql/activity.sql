
SELECT pg_stat_plans_reset() IS NOT NULL AS t;

--
-- check if we see our own plan in activity
--

SELECT plan FROM pg_stat_plans_activity WHERE pid = pg_backend_pid();


--
-- check if we handle showing our plan for named prepared statements correctly
--

PREPARE x AS SELECT plan FROM pg_stat_plans_activity WHERE pid = pg_backend_pid();
EXECUTE x;
DEALLOCATE x;

SELECT pg_stat_plans_reset() IS NOT NULL AS t;
