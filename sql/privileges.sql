--
-- Only superusers and roles with privileges of the pg_read_all_stats role
-- are allowed to see the plan text, queryid and planid of queries executed by
-- other users. Other users can see the statistics.
--

CREATE ROLE regress_stats_superuser SUPERUSER;
CREATE ROLE regress_stats_user1;
CREATE ROLE regress_stats_user2;
GRANT pg_read_all_stats TO regress_stats_user2;

SET ROLE regress_stats_superuser;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SELECT 1 AS "ONE";

SET ROLE regress_stats_user1;
SELECT 1+1 AS "TWO";

--
-- A superuser can read all columns of queries executed by others,
-- including plan text, queryid and planid.
--

SET ROLE regress_stats_superuser;
SELECT r.rolname, ss.queryid <> 0 AS queryid_bool, ss.planid <> 0 AS planid_bool, ss.plan, ss.calls
  FROM pg_stat_plans ss JOIN pg_roles r ON ss.userid = r.oid
  ORDER BY r.rolname, ss.plan COLLATE "C", ss.calls;

--
-- regress_stats_user1 has no privileges to read the plan text, queryid
-- or planid of queries executed by others but can see statistics
-- like calls and rows.
--

SET ROLE regress_stats_user1;
SELECT r.rolname, ss.queryid <> 0 AS queryid_bool, ss.planid <> 0 AS planid_bool, ss.plan, ss.calls
  FROM pg_stat_plans ss JOIN pg_roles r ON ss.userid = r.oid
  ORDER BY r.rolname, ss.plan COLLATE "C", ss.calls;

--
-- regress_stats_user2, with pg_read_all_stats role privileges, can
-- read all columns, including plan text, queryid and planid, of queries
-- executed by others.
--

SET ROLE regress_stats_user2;
SELECT r.rolname, ss.queryid <> 0 AS queryid_bool, ss.planid <> 0 AS planid_bool, ss.plan, ss.calls
  FROM pg_stat_plans ss JOIN pg_roles r ON ss.userid = r.oid
  ORDER BY r.rolname, ss.plan COLLATE "C", ss.calls;

--
-- cleanup
--

RESET ROLE;
DROP ROLE regress_stats_superuser;
DROP ROLE regress_stats_user1;
DROP ROLE regress_stats_user2;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
