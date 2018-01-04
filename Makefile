MODULES = pg_reject_sql
PGFILEDESC = "pg_reject_sql - forbid SQL statements regardless privileges"

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)