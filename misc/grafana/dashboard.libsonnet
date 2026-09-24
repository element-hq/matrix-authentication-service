local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';

local queries = import './queries.libsonnet';
local variables = import './variables.libsonnet';

g.dashboard.new('matrix-authentication-service')
+ g.dashboard.withDescription('A dashboard for monitoring matrix-authentication-service')
+ g.dashboard.withUid('matrix-authentication-service')
+ g.dashboard.withVariables(variables.variables)
+ g.dashboard.graphTooltip.withSharedCrosshair()
+ g.dashboard.withPanels(
  g.util.grid.makeGrid([
    g.panel.row.new('Deployment')
    + g.panel.row.withPanels([
      g.panel.timeSeries.new('Service Version')
      + g.panel.timeSeries.queryOptions.withTargets(queries.serviceVersion)
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.fieldConfig.defaults.custom.withDrawStyle('line')
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(100)
      + g.panel.timeSeries.fieldConfig.defaults.custom.withLineWidth(0)
      + g.panel.timeSeries.fieldConfig.defaults.custom.stacking.withMode('percent'),
    ]),
  ], 24, 6)

  + g.util.grid.makeGrid([
    g.panel.row.new('Tokio')
    + g.panel.row.withCollapsed(true)
    + g.panel.row.withPanels([
      g.panel.stat.new('Workers')
      + g.panel.stat.queryOptions.withTargets(queries.tokio.workers),

      g.panel.heatmap.new('Tick Time')
      + g.panel.heatmap.gridPos.withStatic()
      + g.panel.heatmap.queryOptions.withTargets(queries.tokio.tickTimeHistogram)
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ns'),

      g.panel.timeSeries.new('Tick Time Percentile')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.tokio.tickTimePercentile(0.99),
        queries.tokio.tickTimePercentile(0.95),
        queries.tokio.tickTimePercentile(0.90),
        queries.tokio.tickTimePercentile(0.50),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ns')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.timeSeries.new('Poll Rate')
      + g.panel.timeSeries.queryOptions.withTargets(queries.tokio.pollRate)
      + g.panel.timeSeries.standardOptions.withUnit('ops')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.timeSeries.new('Active Tasks')
      + g.panel.timeSeries.queryOptions.withTargets(queries.tokio.activeTasks)
      + g.panel.timeSeries.standardOptions.withUnit('tasks')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.timeSeries.new('Busy Time')
      + g.panel.timeSeries.queryOptions.withTargets(queries.tokio.busyTime)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),
    ]),
  ], panelHeight=6, startY=100)

  + g.util.grid.makeGrid([
    g.panel.row.new('HTTP server')
    + g.panel.row.withPanels([
      g.panel.timeSeries.new('Requests')
      + g.panel.timeSeries.queryOptions.withTargets(queries.http.requests)
      + g.panel.timeSeries.standardOptions.withUnit('reqps')
      + g.panel.timeSeries.standardOptions.withMin(0)
      + g.panel.timeSeries.options.legend.withPlacement('right')
      + g.panel.timeSeries.options.legend.withDisplayMode('table')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      ,

      g.panel.timeSeries.new('Errors')
      + g.panel.timeSeries.queryOptions.withTargets(queries.http.requestErrors)
      + g.panel.timeSeries.standardOptions.withUnit('reqps')
      + g.panel.timeSeries.standardOptions.withMin(0)
      + g.panel.timeSeries.options.legend.withPlacement('right')
      + g.panel.timeSeries.options.legend.withDisplayMode('table')
      + g.panel.timeSeries.options.legend.withCalcs(['mean']),

      g.panel.heatmap.new('Request latency (excluding introspection)')
      + g.panel.heatmap.queryOptions.withTargets(queries.http.requestLatencyHeatmap('http_route!="/oauth2/introspect"'))
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Request latency percentiles (excluding introspection)')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.http.requestLatencyPercentile(0.99, 'http_route!="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.95, 'http_route!="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.90, 'http_route!="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.50, 'http_route!="/oauth2/introspect"'),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.heatmap.new('Request latency (introspection only)')
      + g.panel.heatmap.queryOptions.withTargets(queries.http.requestLatencyHeatmap('http_route="/oauth2/introspect"'))
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Request latency percentiles (introspection only)')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.http.requestLatencyPercentile(0.99, 'http_route="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.95, 'http_route="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.90, 'http_route="/oauth2/introspect"'),
        queries.http.requestLatencyPercentile(0.50, 'http_route="/oauth2/introspect"'),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),
    ]),
  ], panelWidth=12, startY=200)

  + g.util.grid.makeGrid([
    g.panel.row.new('Database')
    + g.panel.row.withPanels([
      g.panel.heatmap.new('Database connection acquisition latency')
      + g.panel.heatmap.queryOptions.withTargets(queries.database.acquisitionLatencyHeatmap)
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Database connection acquisition latency percentiles')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.database.acquisitionLatencyPercentile(0.99),
        queries.database.acquisitionLatencyPercentile(0.95),
        queries.database.acquisitionLatencyPercentile(0.90),
        queries.database.acquisitionLatencyPercentile(0.50),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.timeSeries.new('Database connection pool usage')
      + g.panel.timeSeries.queryOptions.withTargets(queries.database.poolUsage)
      + g.panel.timeSeries.fieldConfig.defaults.custom.withDrawStyle('line')
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(100)
      + g.panel.timeSeries.fieldConfig.defaults.custom.withLineWidth(0)
      + g.panel.timeSeries.fieldConfig.defaults.custom.stacking.withMode('normal')
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.standardOptions.withMin(0),
    ]),
  ], startY=300)

  + g.util.grid.makeGrid([
    g.panel.row.new('Jobs')
    + g.panel.row.withPanels([
      g.panel.heatmap.new('Job run duration')
      + g.panel.heatmap.queryOptions.withTargets(queries.jobs.durationHistogram)
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Job run P95 per type')
      + g.panel.timeSeries.queryOptions.withTargets(
        queries.jobs.durationPercentilePerType(0.95),
      )
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.timeSeries.new('Job runs')
      + g.panel.timeSeries.queryOptions.withTargets(queries.jobs.rate)
      + g.panel.timeSeries.standardOptions.withUnit('ops')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.heatmap.new('Worker tick duration')
      + g.panel.heatmap.queryOptions.withTargets(queries.jobs.tickHistogram)
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Worker tick duration percentiles')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.jobs.tickPercentile(0.99),
        queries.jobs.tickPercentile(0.95),
        queries.jobs.tickPercentile(0.90),
        queries.jobs.tickPercentile(0.50),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),
    ]),
  ], startY=400)

  + g.util.grid.makeGrid([
    g.panel.row.new('Activity tracker')
    + g.panel.row.withPanels([
      g.panel.timeSeries.new('Record rate')
      + g.panel.timeSeries.queryOptions.withTargets(queries.activityTracker.recordRate)
      + g.panel.timeSeries.standardOptions.withUnit('ops')
      + g.panel.timeSeries.standardOptions.withMin(0),

      g.panel.heatmap.new('Flush time')
      + g.panel.heatmap.queryOptions.withTargets(queries.activityTracker.flushTimeHistogram)
      + g.panel.heatmap.options.withCalculate(false)
      + g.panel.heatmap.options.withCellGap(0)
      + g.panel.heatmap.options.yAxis.withUnit('ms'),

      g.panel.timeSeries.new('Flush time percentiles')
      + g.panel.timeSeries.queryOptions.withTargets([
        queries.activityTracker.flushTimePercentile(0.99),
        queries.activityTracker.flushTimePercentile(0.95),
        queries.activityTracker.flushTimePercentile(0.90),
        queries.activityTracker.flushTimePercentile(0.50),
      ])
      + g.panel.timeSeries.options.tooltip.withMode('multi')
      + g.panel.timeSeries.options.tooltip.withSort('desc')
      + g.panel.timeSeries.options.legend.withCalcs(['mean'])
      + g.panel.timeSeries.fieldConfig.defaults.custom.withFillOpacity(10)
      + g.panel.timeSeries.standardOptions.withUnit('ms')
      + g.panel.timeSeries.standardOptions.withMin(0),
    ]),
  ], startY=500)
)
