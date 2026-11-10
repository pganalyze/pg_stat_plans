--
-- Processes other than regular client backends must be able to use the
-- extension. On Postgres 16 and 17 the stats machinery attaches on first use,
-- since such processes never go through client authentication.
--

-- Reading the view from a parallel worker
SET debug_parallel_query = on;
SELECT count(*) > 0 AS t FROM pg_stat_plans;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
-- Use a different statement than above: On Postgres 18+ a backend that still
-- has unflushed stats for an entry reset by another process (here the parallel
-- worker) keeps using that dropped entry until its next stats flush.
SELECT count(planid) > 0 AS t FROM pg_stat_plans;
RESET debug_parallel_query;
