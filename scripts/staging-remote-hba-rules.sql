WITH hba_rules AS MATERIALIZED (
  SELECT * FROM pg_hba_file_rules
), identities(database_name, role_name) AS (
  VALUES
    (:'approved_db'::text, 'virki_email_worker'::text),
    (:'approved_db'::text, 'virki_runtime'::text),
    (:'approved_db'::text, 'virki_migrator'::text),
    ('postgres'::text, :'bootstrap_user'::text),
    (:'restore_db'::text, :'bootstrap_user'::text),
    (:'restore_db'::text, 'virki_email_worker'::text),
    (:'restore_db'::text, 'virki_runtime'::text),
    (:'restore_db'::text, 'virki_migrator'::text)
), checks AS MATERIALIZED (
  SELECT i.database_name, i.role_name,
    count(r.line_number) FILTER (WHERE NOT (
      r.type = 'hostssl'
      AND r.database = ARRAY[i.database_name]
      AND r.user_name = ARRAY[i.role_name]
      AND r.auth_method = 'scram-sha-256'
      AND coalesce(array_length(r.options, 1), 0) = 0
      AND r.address IS NOT NULL
      AND r.netmask IS NOT NULL
      AND inet_client_addr() IS NOT NULL
      AND family(r.address::inet) = family(inet_client_addr())
      AND family(r.netmask::inet) = family(inet_client_addr())
      AND r.address::inet = inet_client_addr()
      AND r.netmask::inet = CASE family(inet_client_addr())
        WHEN 4 THEN '255.255.255.255'::inet
        ELSE 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'::inet
      END
    )) AS bad_rules,
    count(r.line_number) FILTER (WHERE
      r.type = 'hostssl'
      AND r.database = ARRAY[i.database_name]
      AND r.user_name = ARRAY[i.role_name]
      AND r.auth_method = 'scram-sha-256'
      AND coalesce(array_length(r.options, 1), 0) = 0
      AND r.address IS NOT NULL
      AND r.netmask IS NOT NULL
      AND inet_client_addr() IS NOT NULL
      AND family(r.address::inet) = family(inet_client_addr())
      AND family(r.netmask::inet) = family(inet_client_addr())
      AND r.address::inet = inet_client_addr()
      AND r.netmask::inet = CASE family(inet_client_addr())
        WHEN 4 THEN '255.255.255.255'::inet
        ELSE 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'::inet
      END
    ) AS scram_matches
  FROM identities AS i
  LEFT JOIN hba_rules AS r
    ON r.type <> 'local'
    AND (
      coalesce(r.database, ARRAY[]::text[]) && ARRAY['all', i.database_name, 'sameuser', 'samerole', 'samegroup']
      OR EXISTS (
        SELECT 1 FROM unnest(coalesce(r.database, ARRAY[]::text[])) AS candidate_database(name)
        WHERE name LIKE '/%' OR name LIKE '@%' OR name LIKE '!%'
      )
    )
    AND (
      coalesce(r.user_name, ARRAY[]::text[]) && ARRAY['all', i.role_name]
      OR EXISTS (
        SELECT 1 FROM unnest(coalesce(r.user_name, ARRAY[]::text[])) AS candidate_user(name)
        WHERE name LIKE '+%' OR name LIKE '/%' OR name LIKE '@%' OR name LIKE '!%'
      )
    )
  GROUP BY i.database_name, i.role_name
), checks_summary AS MATERIALIZED (
  SELECT count(*) FILTER (WHERE bad_rules = 0 AND scram_matches = 1) AS passed,
         count(*) AS expected
  FROM checks
), hba_state AS MATERIALIZED (
  SELECT
    (SELECT count(*)::text FROM hba_rules WHERE error IS NOT NULL) AS errors,
    (SELECT count(*)::text FROM hba_rules
     WHERE type <> 'local' AND 'replication' = ANY(coalesce(database, ARRAY[]::text[]))) AS replication_rules,
    (SELECT count(*)::text FROM hba_rules WHERE type <> 'local') AS nonlocal_rules,
    pg_conf_load_time() >= (pg_stat_file(current_setting('hba_file'))).modification AS loaded
)
SELECT passed::text || '|' || expected::text || '|' || errors || '|' || replication_rules || '|' ||
       nonlocal_rules || '|' || loaded::text
FROM checks_summary CROSS JOIN hba_state;
