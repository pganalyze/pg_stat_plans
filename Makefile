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

REGRESS_OPTS = --temp-config $(srcdir)/pg_stat_plans.conf
REGRESS = select activity privileges cleanup

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

# On Postgres 19+, additionally exercise pg_plan_advice collection, but only
# when pg_plan_advice is installed (it must be preloaded for the test). When
# present, preload both modules for the whole run; the extra module is inert
# while pg_stat_plans.plan_advice is "off" (the default), so the other tests
# are unaffected.
ifneq (,$(findstring PostgreSQL 19,$(shell $(PG_CONFIG) --version)))
	PLAN_ADVICE_LIB := $(wildcard $(shell $(PG_CONFIG) --pkglibdir)/pg_plan_advice.*)
	ifneq (,$(PLAN_ADVICE_LIB))
		REGRESS_OPTS = --temp-config $(srcdir)/pg_plan_advice.conf
		REGRESS = select activity privileges plan_advice cleanup
	endif
endif

EXTRA_CLEAN = tmp_check results regression.diffs regression.out

PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)

# Run the regression tests in a throwaway temporary instance created from the
# installed binaries, with pg_stat_plans preloaded via pg_stat_plans.conf.
# Unlike "make installcheck", this does not need a separately running and
# configured server.  Like "make installcheck", it expects the extension to be
# installed first, so run "make install" (or "sudo make install" for a
# system-packaged PostgreSQL) beforehand.
.PHONY: localcheck
localcheck:
	$(top_builddir)/src/test/regress/pg_regress \
		--temp-instance=./tmp_check \
		--bindir='$(bindir)' \
		--inputdir=$(srcdir) \
		$(REGRESS_OPTS) $(REGRESS)
