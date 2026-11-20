# contrib/pg_stat_plans/Makefile

MODULE_big = pg_stat_plans
OBJS = \
	$(WIN32RES) \
	pg_stat_plans.o \
	jumblefuncs.o

EXTENSION = pg_stat_plans
DATA = pg_stat_plans--2.0.sql pg_stat_plans--2.0--2.1.sql
PGFILEDESC = "pg_stat_plans - track per-plan call counts, execution times and EXPLAIN texts"

LDFLAGS_SL += $(filter -lm, $(LIBS))

# The regression tests run in an instance that preloads pg_stat_plans and,
# when they are installed, the modules checked for below. The resulting
# shared_preload_libraries setting is written to regress.conf before the tests
# run (see REGRESS_PREP and the rule at the end).
PRELOAD_LIBRARIES = pg_stat_plans
REGRESS = select activity privileges parallel
REGRESS_OPTS = --temp-config regress.conf
REGRESS_PREP = regress.conf

PG_CFLAGS = $(shell pkg-config --cflags libzstd) $(shell pkg-config --cflags openssl)
PG_LDFLAGS = $(shell pkg-config --libs libzstd)
PG_CONFIG = pg_config

ifneq (,$(findstring PostgreSQL 16,$(shell $(PG_CONFIG) --version)))
	REGRESS_OPTS += --expecteddir=$(PWD)/compat_16_17
	OBJS += compat_16_17/pgstat_custom.o
endif

ifneq (,$(findstring PostgreSQL 17,$(shell $(PG_CONFIG) --version)))
	REGRESS_OPTS += --expecteddir=$(PWD)/compat_16_17
	OBJS += compat_16_17/pgstat_custom.o
endif

ifneq (,$(findstring PostgreSQL 18,$(shell $(PG_CONFIG) --version)))
	REGRESS_OPTS += --expecteddir=$(PWD)/compat_18
endif

# When pg_stat_statements is installed, also exercise running alongside it.
# It is preloaded *before* pg_stat_plans, so that its hooks run after ours and
# see what we leave behind; this is the order in which pg_stat_plans used to
# keep it from tracking utility statements (see the pg_stat_statements test).
# It is inert for the other tests, which only use pg_stat_plans.
PGSS_LIB := $(wildcard $(shell $(PG_CONFIG) --pkglibdir)/pg_stat_statements.*)
ifneq (,$(PGSS_LIB))
	PRELOAD_LIBRARIES := pg_stat_statements,$(PRELOAD_LIBRARIES)
	REGRESS += pg_stat_statements
endif

# On Postgres 19+, additionally exercise pg_plan_advice collection, but only
# when pg_plan_advice is installed (it must be preloaded for the test). The
# extra module is inert while pg_stat_plans.plan_advice is "off" (the
# default), so the other tests are unaffected.
ifneq (,$(filter 19% 20%,$(word 2,$(shell $(PG_CONFIG) --version))))
	PLAN_ADVICE_LIB := $(wildcard $(shell $(PG_CONFIG) --pkglibdir)/pg_plan_advice.*)
	ifneq (,$(PLAN_ADVICE_LIB))
		PRELOAD_LIBRARIES := $(PRELOAD_LIBRARIES),pg_plan_advice
		REGRESS += plan_advice
	endif
endif

REGRESS += cleanup

EXTRA_CLEAN = tmp_check results regression.diffs regression.out regress.conf

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Temporary server configuration for the regression tests, see above.
regress.conf: Makefile
	echo "shared_preload_libraries = '$(PRELOAD_LIBRARIES)'" > $@

# Run the regression tests in a throwaway temporary instance created from the
# installed binaries, with the modules in $(PRELOAD_LIBRARIES) preloaded.
# Unlike "make installcheck", this does not need a separately running and
# configured server.  Like "make installcheck", it expects the extension to be
# installed first, so run "make install" (or "sudo make install" for a
# system-packaged PostgreSQL) beforehand.
.PHONY: localcheck
localcheck: $(REGRESS_PREP)
	$(top_builddir)/src/test/regress/pg_regress \
		--temp-instance=./tmp_check \
		--bindir='$(bindir)' \
		--inputdir=$(srcdir) \
		$(REGRESS_OPTS) $(REGRESS)
