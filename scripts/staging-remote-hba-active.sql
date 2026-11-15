WITH hba_rules AS MATERIALIZED (
  SELECT * FROM pg_hba_file_rules
), hba_file AS MATERIALIZED (
  SELECT current_setting('hba_file') AS path,
         pg_read_file(current_setting('hba_file')) AS contents
), hba_state AS MATERIALIZED (
  SELECT
    pg_conf_load_time() >= (pg_stat_file(hba_file.path)).modification AS loaded,
    (SELECT count(DISTINCT file_name)::text FROM hba_rules) AS file_count,
    (SELECT count(*)::text FROM hba_rules WHERE file_name <> hba_file.path) AS external_files,
    (SELECT count(*)::text FROM hba_rules WHERE error IS NOT NULL) AS errors,
    (SELECT count(*)::text
     FROM regexp_split_to_table(
       replace(
         replace(hba_file.contents, chr(92) || E'\r\n', ''),
         chr(92) || E'\n',
         ''
       ),
       E'\n'
     ) AS hba_line(line)
     -- PostgreSQL 18 dequotes the first HBA token and accepts leading commas.
     -- Even an absent include_if_exists file leaves no parsed rule to count.
     WHERE regexp_replace(hba_line.line, '"', '', 'g') ~*
       '^[[:space:],]*(include|include_if_exists|include_dir)([[:space:],]|$)') AS includes
  FROM hba_file
)
SELECT current_database() || '|' || current_user || '|' ||
       (SELECT rolsuper::text FROM pg_roles WHERE rolname = current_user) || '|' ||
       loaded::text || '|' || file_count || '|' || external_files || '|' ||
       errors || '|' || includes || '|' ||
       coalesce(host(inet_server_addr()), '') || '|' ||
       coalesce(inet_server_port()::text, '') || '|' ||
       coalesce(host(inet_client_addr()), '')
FROM hba_state;
