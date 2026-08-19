-- Switch to a role with ACCOUNTADMIN privileges to create these resources
USE ROLE ACCOUNTADMIN;

-- 1. Create Role
CREATE ROLE IF NOT EXISTS depguard_role;

-- 2. Create Database
CREATE DATABASE IF NOT EXISTS depguard_db;

-- 3. Create Schemas
CREATE SCHEMA IF NOT EXISTS depguard_db.bronze;
CREATE SCHEMA IF NOT EXISTS depguard_db.silver;
CREATE SCHEMA IF NOT EXISTS depguard_db.gold;

-- 4. Create Virtual Warehouse
CREATE WAREHOUSE IF NOT EXISTS depguard_wh
WITH
  WAREHOUSE_SIZE = 'XSMALL'
  AUTO_SUSPEND = 60
  AUTO_RESUME = TRUE
  INITIALLY_SUSPENDED = TRUE;

-- 5. Grant Permissions to the Role
GRANT USAGE ON WAREHOUSE depguard_wh TO ROLE depguard_role;
GRANT USAGE ON DATABASE depguard_db TO ROLE depguard_role;
GRANT USAGE ON ALL SCHEMAS IN DATABASE depguard_db TO ROLE depguard_role;
GRANT USAGE ON FUTURE SCHEMAS IN DATABASE depguard_db TO ROLE depguard_role;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA depguard_db.bronze TO ROLE depguard_role;
GRANT ALL PRIVILEGES ON FUTURE TABLES IN SCHEMA depguard_db.bronze TO ROLE depguard_role;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA depguard_db.silver TO ROLE depguard_role;
GRANT ALL PRIVILEGES ON FUTURE TABLES IN SCHEMA depguard_db.silver TO ROLE depguard_role;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA depguard_db.gold TO ROLE depguard_role;
GRANT ALL PRIVILEGES ON FUTURE TABLES IN SCHEMA depguard_db.gold TO ROLE depguard_role;

-- 6. Grant Role to the user who ran this script
SET current_user_name = CURRENT_USER();
GRANT ROLE depguard_role TO USER IDENTIFIER($current_user_name);
