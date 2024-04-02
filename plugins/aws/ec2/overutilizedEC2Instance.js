var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 CPU Alarm Threshold Exceeded',
    category: 'EC2',
    domain: 'Compute',
    severity: 'High',
    description: 'Ensure EC2 instances do not exceed the alarm threshold for CPU utilization.',
    more_info: 'Excessive CPU utilization can indicate performance issues or the need for capacity optimization.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_metrics_with_cloudwatch.html#ec2-cloudwatch-metrics',
    recommended_action: 'Investigate the cause of high CPU utilization and consider optimizing or scaling resources.',
    apis: ['EC2:describeInstances', 'CloudWatch:getEc2MetricStatistics'],
    settings: {
        ec2_cpu_threshold_fail: {
            name: 'EC2 CPU Threshold Fail',
            description: 'Return a failing result when consumed EC2 insatnce cpu threshold equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: '90'
        }
    },
    realtime_triggers: ['ec2:RunInstances', 'ec2:ModifyInstanceAttribute', 'ec2:TerminateInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var ec2_cpu_threshold_fail = settings.ec2_cpu_threshold_fail || this.settings.ec2_cpu_threshold_fail.default;

        async.each(regions.ec2, function(region, rcb) {
            var describeInstances = helpers.addSource(cache, source,
                ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for EC2 instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            describeInstances.data.forEach(reservation => {
                let accountId = reservation.OwnerId;
                reservation.Instances.forEach(instance => {
                    if (!instance.InstanceId) return;
                    let resource = `arn:${awsOrGov}:ec2:` + region + ':' + accountId + ':instance/' + instance.InstanceId;
                    var getMetricStatistics = helpers.addSource(cache, source,
                        ['cloudwatch', 'getEc2MetricStatistics', region, instance.InstanceId]);

                    if (!getMetricStatistics || getMetricStatistics.err ||
            !getMetricStatistics.data || !getMetricStatistics.data.Datapoints) {
                        helpers.addResult(results, 3,
                            `Unable to query for CPU metric statistics: ${helpers.addError(getMetricStatistics)}`, region, resource);
                        return;
                    }

                    if (!getMetricStatistics.data.Datapoints.length) {
                        helpers.addResult(results, 0,
                            'CPU metric statistics are not available', region, resource);
                    } else {
                        var cpuDatapoints = getMetricStatistics.data.Datapoints;
                        var cpuUtilization = cpuDatapoints[cpuDatapoints.length - 1].Average;
                        if (cpuUtilization >= ec2_cpu_threshold_fail) {
                            helpers.addResult(results, 2,
                                `EC2 instance has current CPU utilization of ${cpuUtilization}% which exceeds the CPU threshold`, region, resource);
                        } else {
                            helpers.addResult(results, 0,
                                `EC2 instance has current CPU utilization of ${cpuUtilization}% which does not exceed the CPU threshold`, region, resource);
                        }
                    }
                });
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
