#!/bin/sh
# Apply migrations, prepare the cache table and seed the knowledge base (all idempotent).
set -e
python manage.py migrate --noinput
python manage.py createcachetable
python manage.py load_catalog
exec "$@"
