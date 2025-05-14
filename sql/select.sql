--
-- SELECT statements
--

CREATE EXTENSION pg_stat_plans;
SELECT pg_stat_plans_reset() IS NOT NULL AS t;

--
-- simple statements
--

SELECT 1 FROM pg_class LIMIT 1;

SELECT 1 FROM pg_class WHERE relname = 'pg_class';

SET enable_indexscan = off;
SELECT 1 FROM pg_class WHERE relname = 'pg_class';
SET enable_indexscan = on;

SELECT plan, calls FROM pg_stat_plans ORDER BY plan COLLATE "C";
SELECT pg_stat_plans_reset() IS NOT NULL AS t;

--
-- subplans and CTEs
--

WITH x AS MATERIALIZED (SELECT 1)
SELECT * FROM x;

SELECT a.attname,
   (SELECT pg_catalog.pg_get_expr(d.adbin, d.adrelid)
    FROM pg_catalog.pg_attrdef d
    WHERE d.adrelid = a.attrelid AND d.adnum = a.attnum AND a.atthasdef)
 FROM pg_catalog.pg_attribute a
 WHERE a.attrelid = 'pg_class'::regclass
 ORDER BY attnum LIMIT 1;

SELECT plan, calls FROM pg_stat_plans ORDER BY plan COLLATE "C";
SELECT pg_stat_plans_reset() IS NOT NULL AS t;

--
-- partitoning
--

create table lp (a char) partition by list (a);
create table lp_default partition of lp default;
create table lp_ef partition of lp for values in ('e', 'f');
create table lp_ad partition of lp for values in ('a', 'd');
create table lp_bc partition of lp for values in ('b', 'c');
create table lp_g partition of lp for values in ('g');
create table lp_null partition of lp for values in (null);

select * from lp;
select * from lp where a > 'a' and a < 'd';
select * from lp where a > 'a' and a <= 'd';
select * from lp where a = 'a';
select * from lp where 'a' = a;	/* commuted */
select * from lp where a is not null;
select * from lp where a is null;
select * from lp where a = 'a' or a = 'c';
select * from lp where a is not null and (a = 'a' or a = 'c');
select * from lp where a <> 'g';
select * from lp where a <> 'a' and a <> 'd';
select * from lp where a not in ('a', 'd');

SELECT plan, calls FROM pg_stat_plans ORDER BY plan COLLATE "C";
SELECT pg_stat_plans_reset() IS NOT NULL AS t;
