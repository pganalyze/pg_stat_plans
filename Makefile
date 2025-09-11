# contrib/pg_stat_plans/Makefile

MODULE_big = pg_stat_plans
OBJS = \
	$(WIN32RES) \
	pg_stat_plans.o \
	pgstat_custom.o \
	jumblefuncs.o

EXTENSION = pg_stat_plans
DATA = pg_stat_plans--2.0.sql
PGFILEDESC = "pg_stat_plans - track per-plan call counts, execution times and EXPLAIN texts"

LDFLAGS_SL += $(filter -lm, $(LIBS))

REGRESS_OPTS = --temp-config $(top_srcdir)/contrib/pg_stat_plans/pg_stat_plans.conf
REGRESS = select activity privileges cleanup

PG_CFLAGS = $(shell pkg-config --cflags libzstd)
PG_LDFLAGS = $(shell pkg-config --libs libzstd)
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
