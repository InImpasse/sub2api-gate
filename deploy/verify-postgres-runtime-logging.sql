\set ON_ERROR_STOP on

BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY;

WITH expected_settings(name, setting) AS (
    VALUES
        ('logging_collector', 'off'),
        ('log_destination', 'stderr'),
        ('log_directory', 'log'),
        ('log_statement', 'none'),
        ('log_min_error_statement', 'panic'),
        ('log_min_messages', 'panic'),
        ('log_error_verbosity', 'terse'),
        ('log_parameter_max_length', '0'),
        ('log_parameter_max_length_on_error', '0'),
        ('log_duration', 'off'),
        ('log_min_duration_statement', '-1'),
        ('log_min_duration_sample', '-1'),
        ('log_statement_sample_rate', '0'),
        ('log_transaction_sample_rate', '0'),
        ('log_connections', 'off'),
        ('log_disconnections', 'off'),
        ('log_replication_commands', 'off'),
        ('log_checkpoints', 'off'),
        ('log_lock_waits', 'off'),
        ('log_temp_files', '-1'),
        ('log_autovacuum_min_duration', '-1'),
        ('debug_print_parse', 'off'),
        ('debug_print_rewritten', 'off'),
        ('debug_print_plan', 'off'),
        ('log_parser_stats', 'off'),
        ('log_planner_stats', 'off'),
        ('log_executor_stats', 'off'),
        ('log_statement_stats', 'off')
), safe_settings AS (
    SELECT COUNT(*) = (SELECT COUNT(*) FROM expected_settings)
       AND COALESCE(bool_and(
            settings.setting = expected.setting
            AND settings.source = 'command line'
            AND NOT settings.pending_restart
       ), false) AS installed
    FROM expected_settings AS expected
    JOIN pg_catalog.pg_settings AS settings USING (name)
), runtime_paths AS (
    SELECT current_setting('data_directory') AS data_directory,
           current_setting('log_directory') AS log_directory
), configured_log_directories AS (
    SELECT runtime_paths.data_directory, runtime_paths.log_directory
    FROM runtime_paths
    UNION
    SELECT runtime_paths.data_directory, file_settings.setting
    FROM runtime_paths
    CROSS JOIN pg_catalog.pg_file_settings AS file_settings
    WHERE file_settings.name = 'log_directory'
      AND file_settings.setting IS NOT NULL
), resolved_paths AS (
    SELECT data_directory,
           CASE
               WHEN left(log_directory, 1) = '/' THEN log_directory
               ELSE data_directory || '/' || log_directory
           END AS log_directory
    FROM configured_log_directories
), safe_files AS (
    SELECT NOT EXISTS (
            SELECT 1
            FROM runtime_paths
            WHERE (
                      pg_catalog.pg_stat_file('current_logfiles', true)
                  ).size IS NOT NULL
       )
       AND NOT EXISTS (
            SELECT 1
            FROM resolved_paths
            CROSS JOIN LATERAL pg_catalog.pg_ls_dir(
                resolved_paths.log_directory, true, false
            )
       ) AS absent
)
SELECT safe_settings.installed AND safe_files.absent
       AS postgres_runtime_logging_safe
FROM safe_settings CROSS JOIN safe_files
\gset

\if :postgres_runtime_logging_safe
\else
    SELECT 1 / 0;
\endif

ROLLBACK;
