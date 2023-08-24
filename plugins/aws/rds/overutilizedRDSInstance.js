var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS CPU Alarm Threshold Exceeded',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure RDS instances do not exceed the alarm threshold for CPU utilization.',
    more_info: 'Excessive CPU utilization can indicate that the databases running on these servers do not have enough hardware resources to perform optimally.Upgrading overutilized RDS instances to meet the load needs will improve directly the health and success of databases.',
    link: 'https://docs.aws.amazon.com/prescriptive-guidance/latest/amazon-rds-monitoring-alerting/db-instance-cloudwatch-metrics.html',
    recommended_action: 'Upgrade (upsize) the overused RDS database instances.',
    apis: ['RDS:describeDBInstances', 'CloudWatch:getRdsMetricStatistics'],
    settings: {
        rds_cpu_threshold_fail: {
            name: 'RDS Instance CPU Threshold Fail',
            description: 'Return a failing result when consumed RDS insatnce cpu threshold equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var rds_cpu_threshold_fail = settings.rds_cpu_threshold_fail || this.settings.rds_cpu_threshold_fail.default;

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for RDS instances: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn) return;

                var getMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getRdsMetricStatistics', region, instance.DBInstanceIdentifier]);

                if (!getMetricStatistics || getMetricStatistics.err || !getMetricStatistics.data || !getMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3,
                        `Unable to query for CPU metric statistics: ${helpers.addError(getMetricStatistics)}`, region, instance.DBInstanceArn);
                    return;
                }

                if (!getMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0,
                        'CPU metric statistics are not available', region, instance.DBInstanceArn);
                } else {
                    var cpuDatapoints = getMetricStatistics.data.Datapoints;
                    var cpuUtilization = cpuDatapoints[cpuDatapoints.length - 1].Average;
                    if (cpuUtilization >= rds_cpu_threshold_fail) {
                        helpers.addResult(results, 2,
                            `RDS instance has current CPU utilization of ${cpuUtilization}% which exceeds the CPU threshold`, region, instance.DBInstanceArn);
                    } else {
                        helpers.addResult(results, 0,
                            `RDS instance has current CPU utilization of ${cpuUtilization}% which does not exceed the CPU threshold`, region, instance.DBInstanceArn);
                    }
                }
            });
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
