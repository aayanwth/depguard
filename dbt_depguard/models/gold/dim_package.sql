{{ config(materialized='table') }}

SELECT 
    -- md5 works differently in duckdb vs snowflake if handling nulls, simple concat string is fine
    md5(package_name || ecosystem) AS package_sk,
    package_name,
    ecosystem,
    last_seen_at
FROM {{ ref('silver_packages') }}
