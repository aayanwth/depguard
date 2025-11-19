# Snowflake resources for DepGuard. Mirrors scripts/snowflake_init.sql, so use
# one or the other, not both.
#
#   export TF_VAR_snowflake_password=...
#   terraform init && terraform apply -var snowflake_organization_name=... \
#       -var snowflake_account_name=... -var snowflake_user=...

terraform {
  required_providers {
    snowflake = {
      source  = "Snowflake-Labs/snowflake"
      version = "~> 0.98"
    }
  }
}

variable "snowflake_organization_name" {
  type = string
}

variable "snowflake_account_name" {
  type = string
}

variable "snowflake_user" {
  type = string
}

variable "snowflake_password" {
  type      = string
  sensitive = true
}

provider "snowflake" {
  organization_name = var.snowflake_organization_name
  account_name      = var.snowflake_account_name
  user              = var.snowflake_user
  password          = var.snowflake_password
  role              = "ACCOUNTADMIN"
}

locals {
  schemas = ["BRONZE", "SILVER", "GOLD"]
}

resource "snowflake_account_role" "depguard" {
  name = "DEPGUARD_ROLE"
}

resource "snowflake_database" "depguard" {
  name = "DEPGUARD_DB"
}

resource "snowflake_schema" "layers" {
  for_each = toset(local.schemas)
  database = snowflake_database.depguard.name
  name     = each.value
}

resource "snowflake_warehouse" "depguard" {
  name                = "DEPGUARD_WH"
  warehouse_size      = "XSMALL"
  auto_suspend        = 60
  auto_resume         = "true"
  initially_suspended = true
}

resource "snowflake_grant_privileges_to_account_role" "warehouse_usage" {
  account_role_name = snowflake_account_role.depguard.name
  privileges        = ["USAGE"]
  on_account_object {
    object_type = "WAREHOUSE"
    object_name = snowflake_warehouse.depguard.name
  }
}

resource "snowflake_grant_privileges_to_account_role" "database_usage" {
  account_role_name = snowflake_account_role.depguard.name
  privileges        = ["USAGE"]
  on_account_object {
    object_type = "DATABASE"
    object_name = snowflake_database.depguard.name
  }
}

resource "snowflake_grant_privileges_to_account_role" "schema_privileges" {
  for_each          = snowflake_schema.layers
  account_role_name = snowflake_account_role.depguard.name
  all_privileges    = true
  on_schema {
    schema_name = "\"${snowflake_database.depguard.name}\".\"${each.value.name}\""
  }
}

resource "snowflake_grant_privileges_to_account_role" "existing_tables" {
  for_each          = snowflake_schema.layers
  account_role_name = snowflake_account_role.depguard.name
  all_privileges    = true
  on_schema_object {
    all {
      object_type_plural = "TABLES"
      in_schema          = "\"${snowflake_database.depguard.name}\".\"${each.value.name}\""
    }
  }
}

resource "snowflake_grant_privileges_to_account_role" "future_tables" {
  for_each          = snowflake_schema.layers
  account_role_name = snowflake_account_role.depguard.name
  all_privileges    = true
  on_schema_object {
    future {
      object_type_plural = "TABLES"
      in_schema          = "\"${snowflake_database.depguard.name}\".\"${each.value.name}\""
    }
  }
}

# Give the role to the user that runs the pipeline.
resource "snowflake_grant_account_role" "to_user" {
  role_name = snowflake_account_role.depguard.name
  user_name = var.snowflake_user
}
