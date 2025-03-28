local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
local prometheusQuery = g.query.prometheus;
local variables = import './variables.libsonnet';

local datasource = '${%s}' % variables.datasource.name;

{
  serviceVersion:
    prometheusQuery.new(
      datasource,
      'sum by (service_version) (target_info{%s})'
      % [variables.selectors],
    )
    + prometheusQuery.withLegendFormat('{{service_version}}'),

  tokio: {
    tickTimeHistogram:
      prometheusQuery.new(
        datasource,
        'sum by (le) (irate(tokio_runtime_worker_poll_time_bucket{%s}[$__rate_interval]))'
        % [variables.selectors],
      )
      + prometheusQuery.withFormat('heatmap'),

    tickTimePercentile(percentile):
      prometheusQuery.new(
        datasource,
        'histogram_quantile(%0.2f, sum by (le) (irate(tokio_runtime_worker_poll_time_bucket{%s}[$__rate_interval])))'
        % [percentile, variables.selectors],
      )
      + prometheusQuery.withLegendFormat('P%02d' % (percentile * 100))
      + prometheusQuery.withRefId('P%02d' % (percentile * 100)),

    pollRate:
      prometheusQuery.new(
        datasource,
        'sum(irate(tokio_runtime_worker_polls_total{%s}[$__rate_interval]))'
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('Polls'),

    activeTasks:
      prometheusQuery.new(
        datasource,
        'sum(tokio_runtime_alive_tasks{%s})'
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('Active Tasks'),

    busyTime:
      prometheusQuery.new(
        datasource,
        'sum(irate(tokio_runtime_worker_busy_duration_milliseconds_total{%s}[$__rate_interval]))'
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('Worker busy Time'),

    workers:
      prometheusQuery.new(
        datasource,
        'sum(tokio_runtime_workers{%s})'
        % [variables.selectors],
      ),
  },

  http: {
    requests:
      prometheusQuery.new(
        datasource,
        |||
          sum by (http_request_method, http_route, http_response_status_code )
          (irate(http_server_duration_count{%s}[$__rate_interval]))
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('{{http_request_method}} {{http_route}} {{http_response_status_code}}'),

    requestErrors:
      prometheusQuery.new(
        datasource,
        |||
          sum by (http_request_method, http_route, http_response_status_code)
          (irate(http_server_duration_count{%s, http_response_status_code=~"4..|5.."}[$__rate_interval]))
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('{{http_request_method}} {{http_route}} {{http_response_status_code}}'),

    requestLatencyHeatmap(selector=''):
      prometheusQuery.new(
        datasource,
        |||
          sum by (le) (
            irate(http_server_duration_bucket{%s, %s}[$__rate_interval])
          )
        |||
        % [variables.selectors, selector],
      )
      + prometheusQuery.withFormat('heatmap'),

    requestLatencyPercentile(percentile, selector=''):
      prometheusQuery.new(
        datasource,
        |||
          histogram_quantile(%0.2f, sum by (le) (
            irate(http_server_duration_bucket{%s, %s}[$__rate_interval])
          ))
        |||
        % [percentile, variables.selectors, selector],
      )
      + prometheusQuery.withLegendFormat('P%02d' % (percentile * 100))
      + prometheusQuery.withRefId('P%02d' % (percentile * 100)),
  },

  database: {
    acquisitionLatencyHeatmap:
      prometheusQuery.new(
        datasource,
        |||
          sum by (le) (
            irate(db_client_connections_create_time_milliseconds_bucket{%s}[$__rate_interval])
          )
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withFormat('heatmap'),

    acquisitionLatencyPercentile(percentile):
      prometheusQuery.new(
        datasource,
        |||
          histogram_quantile(%0.2f, sum by (le) (
            irate(db_client_connections_create_time_milliseconds_bucket{%s}[$__rate_interval])
          ))
        |||
        % [percentile, variables.selectors],
      )
      + prometheusQuery.withLegendFormat('P%02d' % (percentile * 100)),

    poolUsage:
      prometheusQuery.new(
        datasource,
        |||
          sum by (state) (db_connections_usage{%s})
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('Connection {{state}}'),
  },

  jobs: {
    durationHistogram:
      prometheusQuery.new(
        datasource,
        |||
          sum by (le) (
            irate(job_process_duration_milliseconds_bucket{%s}[$__rate_interval])
          )
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withFormat('heatmap'),

    durationPercentilePerType(percentile):
      prometheusQuery.new(
        datasource,
        |||
          histogram_quantile(%0.2f, sum by (le, job_queue_name) (
            irate(job_process_duration_milliseconds_bucket{%s}[$__rate_interval])
          ))
        |||
        % [percentile, variables.selectors],
      )
      + prometheusQuery.withLegendFormat('{{job_queue_name}}')
      + prometheusQuery.withRefId('P%02d' % (percentile * 100)),

    rate:
      prometheusQuery.new(
        datasource,
        |||
          sum by(job_queue_name, job_result)
          (irate(job_process_duration_milliseconds_count{%s}[$__rate_interval]))
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('{{job_queue_name}} {{job_result}}'),

    tickHistogram:
      prometheusQuery.new(
        datasource,
        |||
          sum by (le) (
            irate(job_worker_tick_duration_bucket{%s}[$__rate_interval])
          )
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withFormat('heatmap'),

    tickPercentile(percentile):
      prometheusQuery.new(
        datasource,
        |||
          histogram_quantile(%0.2f, sum by (le) (
            irate(job_worker_tick_duration_bucket{%s}[$__rate_interval])
          ))
        |||
        % [percentile, variables.selectors],
      )
      + prometheusQuery.withLegendFormat('P%02d' % (percentile * 100))
      + prometheusQuery.withRefId('P%02d' % (percentile * 100)),
  },

  activityTracker: {
    recordRate:
      prometheusQuery.new(
        datasource,
        |||
          sum by(session_kind)
          (irate(mas_activity_tracker_messages_total{%s, type="record"}[$__rate_interval]))
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withLegendFormat('{{session_kind}}'),

    flushTimeHistogram:
      prometheusQuery.new(
        datasource,
        |||
          sum by (le) (
            irate(mas_activity_tracker_flush_time_milliseconds_bucket{%s}[$__rate_interval])
          )
        |||
        % [variables.selectors],
      )
      + prometheusQuery.withFormat('heatmap'),

    flushTimePercentile(percentile):
      prometheusQuery.new(
        datasource,
        |||
          histogram_quantile(%0.2f, sum by (le) (
            irate(mas_activity_tracker_flush_time_milliseconds_bucket{%s}[$__rate_interval])
          ))
        |||
        % [percentile, variables.selectors],
      )
      + prometheusQuery.withLegendFormat('P%02d' % (percentile * 100))
      + prometheusQuery.withRefId('P%02d' % (percentile * 100)),
  },
}
