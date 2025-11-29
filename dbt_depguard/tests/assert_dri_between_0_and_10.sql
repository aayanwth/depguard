-- Returns offending rows; the test passes when none are returned.
SELECT incident_sk, dependency_risk_index
FROM {{ ref('fact_vulnerability_incident') }}
WHERE dependency_risk_index < 0 OR dependency_risk_index > 10
