--
-- Plan texts are recorded in the encoding of the database the plan ran in,
-- and converted to the reading database's encoding. One entry whose text
-- can't be returned must not fail the whole read; its plan is NULL (#29).
--

SELECT current_database() AS orig_db \gset

CREATE DATABASE regress_pgsp_utf8 TEMPLATE template0 ENCODING 'UTF8'
  LOCALE_PROVIDER libc LOCALE 'C';
CREATE DATABASE regress_pgsp_latin1 TEMPLATE template0 ENCODING 'LATIN1'
  LOCALE_PROVIDER libc LOCALE 'C';

\c regress_pgsp_utf8
SET client_encoding = 'UTF8';
CREATE EXTENSION pg_stat_plans;
SET pg_stat_plans.compress = none;
CREATE TABLE pgsp_enc_clip (v text);
CREATE TABLE pgsp_enc_acute (v text);
CREATE TABLE pgsp_enc_euro (v text);

--
-- Truncating a plan text at max_size must not split a multibyte character.
-- The run of two-byte characters straddles the limit, so of two adjacent
-- limits exactly one falls inside a character, which is then left out.
--

SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SET pg_stat_plans.max_size = 150;
SELECT * FROM pgsp_enc_clip WHERE v <> repeat('é', 100);
RESET pg_stat_plans.max_size;
SELECT octet_length(plan) AS bytes_150 FROM pg_stat_plans
  WHERE plan LIKE 'Seq Scan on pgsp_enc_clip%' \gset
SELECT :bytes_150 BETWEEN 149 AND 150 AS within_limit,
       right(plan, 1) = 'é' AS ends_with_whole_char
  FROM pg_stat_plans WHERE plan LIKE 'Seq Scan on pgsp_enc_clip%';

SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SET pg_stat_plans.max_size = 151;
SELECT * FROM pgsp_enc_clip WHERE v <> repeat('é', 100);
RESET pg_stat_plans.max_size;
SELECT octet_length(plan) AS bytes_151 FROM pg_stat_plans
  WHERE plan LIKE 'Seq Scan on pgsp_enc_clip%' \gset
SELECT :bytes_151 BETWEEN 150 AND 151 AS within_limit,
       right(plan, 1) = 'é' AS ends_with_whole_char
  FROM pg_stat_plans WHERE plan LIKE 'Seq Scan on pgsp_enc_clip%';

-- Exactly one of the two limits fell inside a character
SELECT (150 - :bytes_150) + (151 - :bytes_151) AS bytes_clipped;

--
-- An entry whose text has no equivalent in the reading database's encoding
-- is returned with a NULL plan, while other entries convert as usual.
--

SELECT pg_stat_plans_reset() IS NOT NULL AS t;
SELECT * FROM pgsp_enc_acute WHERE v <> 'é';
SELECT * FROM pgsp_enc_euro WHERE v <> '€';

-- Wait for pending stats to be flushed
SELECT pg_sleep(1);

SELECT queryid AS acute_queryid, planid AS acute_planid FROM pg_stat_plans
  WHERE plan LIKE 'Seq Scan on pgsp_enc_acute%' \gset
SELECT queryid AS euro_queryid, planid AS euro_planid FROM pg_stat_plans
  WHERE plan LIKE 'Seq Scan on pgsp_enc_euro%' \gset

\c regress_pgsp_latin1
SET client_encoding = 'UTF8';
CREATE EXTENSION pg_stat_plans;

-- '€' does not exist in LATIN1
SELECT plan IS NULL AS plan_is_null, calls
  FROM pg_stat_plans WHERE queryid = :euro_queryid AND planid = :euro_planid;
-- 'é' does
SELECT plan LIKE '%''é''%' AS plan_converted, calls
  FROM pg_stat_plans WHERE queryid = :acute_queryid AND planid = :acute_planid;

-- Statistics only
SELECT calls FROM pg_stat_plans(false)
  WHERE queryid = :euro_queryid AND planid = :euro_planid;

SELECT pg_stat_plans_reset() IS NOT NULL AS t;

\c :orig_db
DROP DATABASE regress_pgsp_utf8;
DROP DATABASE regress_pgsp_latin1;
