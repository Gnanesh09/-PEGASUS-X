-- Run inside pegasus_lab as postgres after 01_create_lab.sql.
SELECT current_database() AS database_name;
SELECT rolname, rolcanlogin FROM pg_roles WHERE rolname IN ('pegasus_app','pegasus_test');
SELECT
  has_table_privilege('pegasus_app', 'public.demo_customers', 'SELECT') AS app_can_read_demo,
  has_table_privilege('pegasus_test', 'public.demo_customers', 'SELECT') AS test_can_read_demo,
  has_table_privilege('pegasus_test', 'public.restricted_demo', 'SELECT') AS test_can_read_restricted;
-- Expected: app_can_read_demo=true, test_can_read_demo=true, test_can_read_restricted=false.
