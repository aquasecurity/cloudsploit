var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'EC2 CPU Alarm Threshold Exceeded',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensure EC2 instances do not exceed the alarm threshold for CPU utilization.',
    more_info: 'Excessive CPU utilization can indicate performance issues or the need for capacity optimization.',
    link: 'https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-cloudwatch.html',
    recommended_action: 'Investigate the cause of high CPU utilization and consider optimizing or scaling resources.',
    apis: ['EC2:describeInstances', 'CloudWatch:getEc2MetricStatistics'],
    settings: {
        ec2_cpu_threshold_fail: {
            name: 'EC2 CPU Threshold Fail',
            description: 'Return a failing result when consumed EC2 insatnce cpu threshold equals or exceeds this percentage',
            regex: '^(100(\.0{1,2})?|[1-9]?\d(\.\d{1,2})?)$',
            default: '90.00'
        },
        ec2_cpu_threshold_warn: {
            name: 'EC2 CPU Threshold Warn',
            description: 'Return a warning result when consumed EC2 insatnce cpu threshold equals or exceeds this percentage',
            regex: '^(100(\.0{1,2})?|[1-9]?\d(\.\d{1,2})?)$',
            default: '75.00'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            ec2_cpu_threshold_fail: settings.ec2_cpu_threshold_fail || this.settings.ec2_cpu_threshold_fail.default,
            ec2_cpu_threshold_warn: settings.ec2_cpu_threshold_warn || this.settings.ec2_cpu_threshold_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

       // cpu_threshold = parseFloat(cpu_threshold);

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
                reservation.Instances.forEach(instance => {
                    if (!instance.InstanceId) return;

                    var resource = instance.InstanceId;
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
                        if (cpuUtilization >= config.ec2_cpu_threshold_fail) {
                            helpers.addResult(results, 2,
                                `EC2 instance has current CPU utilization of ${cpuUtilization}% which exceeds the CPU threshold`, region, resource);
                        } else if (cpuUtilization >= config.ec2_cpu_threshold_warn){
                            helpers.addResult(results, 1,
                                `EC2 instance has current CPU utilization of ${cpuUtilization}% which exceed the warning CPU threshold`, region, resource);
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
