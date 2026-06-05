# Changelog

## 2.1.0   2026-06-05

* Postgres 19 support
* Optionally capture plan advice string on Postgres 19
  - When enabled with the new pg_stat_plans.plan_advice setting, plan advice
    will be tracked during each query's planning cycle, and the generated
    advice will be stored in shared memory for the first execution of a given
    plan ID. This is similar to running EXPLAIN (PLAN_ADVICE) on the query
    and helps determine the advice strings that can reproduce a given plan.
* Add pg_stat_plans.max_plan_memory setting to total plan text memory
  - Previously the limit was implicitly calculated from the max * max_size,
    but plan text sizes can be quite uneven, and its easier to reason about
    a fixed limit. Together with this change, rework how the plan text limit
    is implemented, by relying on dsa_set_size_limit.
  - The new default limit is 16MB, up from the prior implicit 10MB. Due to
    max_size now being uncoupled from the actual limit, also raise the default
    max_size to 8kb of (potentially compressed) plan text. This default is
    chosen to optimize for the DSA handling of "smaller entries" that avoids
    allocating full DSA pages. Entries that go over the limit will have a
    blank value for plan text.
* Correctness/scaling improvements
  - Use pending statistics correctly to fix data race
  - Prevent concurrent garbage collection cycles
  - Eagerly free plan text when dropping entries to support resurrection
* Maintenance improvements
  - Regenerate jumble funcs from Postgres sources using script
  - Avoid unused warning for _jumblElements, drop RecordConstLocation
  -  Fix compiler warnings
  - Fix regression tests for Postgres 16+17, move pgstat_custom for clarity


## 2.0.0   2025-09-11

* Initial release

