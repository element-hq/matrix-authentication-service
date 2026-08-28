local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
local var = g.dashboard.variable;

{
  datasource:
    var.datasource.new('datasource', 'prometheus')
    + var.query.selectionOptions.withIncludeAll(false)
    + var.query.selectionOptions.withMulti(false)
    + var.query.refresh.onLoad(),

  job:
    var.query.new('job')
    + var.query.withDatasourceFromVariable(self.datasource)
    + var.query.queryTypes.withLabelValues('job', 'target_info')
    + var.query.selectionOptions.withIncludeAll(true)
    + var.query.selectionOptions.withMulti(false)
    + var.query.refresh.onLoad(),

  instance:
    var.query.new('instance')
    + var.query.withDatasourceFromVariable(self.datasource)
    + var.query.queryTypes.withLabelValues(
      'instance',
      'target_info{job=~"$%s"}' % [self.job.name],
    )
    + var.query.selectionOptions.withIncludeAll(true, '.*')
    + var.query.selectionOptions.withMulti(false)
    + var.query.refresh.onTime(),

  variables: [
    self.datasource,
    self.job,
    self.instance,
  ],

  selectors: 'job=~"$%s", instance=~"$%s"' % [
    self.job.name,
    self.instance.name,
  ],
}
