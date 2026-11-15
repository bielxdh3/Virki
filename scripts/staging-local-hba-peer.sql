WITH hba_rules AS MATERIALIZED (
  SELECT * FROM pg_hba_file_rules
), hba_file AS MATERIALIZED (
  SELECT current_setting('hba_file') AS path,
         pg_read_file(current_setting('hba_file')) AS contents
), hba_state AS MATERIALIZED (
  SELECT
    (SELECT count(*)::text FROM hba_rules WHERE type = 'local') AS local_rules,
    (SELECT count(*)::text FROM hba_rules
     WHERE type = 'local' AND database = ARRAY['postgres']
       AND user_name = ARRAY[current_user::text] AND auth_method = 'peer'
       AND coalesce(array_length(options, 1), 0) = 0) AS postgres_peer_rules,
    (SELECT count(*)::text FROM hba_rules
     WHERE type = 'local' AND database = ARRAY[:'restore_db']
       AND user_name = ARRAY[current_user::text] AND auth_method = 'peer'
       AND coalesce(array_length(options, 1), 0) = 0) AS restore_peer_rules,
    (SELECT count(*)::text FROM hba_rules WHERE error IS NOT NULL) AS errors,
    (SELECT count(DISTINCT file_name)::text FROM hba_rules) AS files,
    (SELECT count(*)::text FROM hba_rules WHERE file_name <> hba_file.path) AS external_rules,
    (SELECT count(*)::text
     FROM regexp_split_to_table(
       replace(
         replace(hba_file.contents, chr(92) || E'\r\n', ''),
         chr(92) || E'\n',
         ''
       ),
       E'\n'
     ) AS hba_line(line)
     WHERE regexp_replace(hba_line.line, '^[[:space:]]+', '') ~*
       '^(include|include_if_exists|include_dir)([[:space:]]|$)') AS includes,
    pg_conf_load_time() >= (pg_stat_file(hba_file.path)).modification AS loaded,
    hba_file.path AS path
  FROM hba_file
)
SELECT current_database() || '|' || current_user || '|' || session_user || '|' ||
       current_setting('port') || '|' ||
       floor(extract(epoch from pg_postmaster_start_time()))::bigint::text || '|' ||
       (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user) || '|' ||
       local_rules || '|' || postgres_peer_rules || '|' || restore_peer_rules || '|' ||
       errors || '|' || includes || '|' || path || '|' || loaded::text || '|' ||
       files || '|' || external_rules
FROM hba_state;
