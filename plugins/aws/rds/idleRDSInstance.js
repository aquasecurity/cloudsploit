var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Idle Instance Status',
    category: 'RDS',
    domain: 'Databases',
    description: 'Identify RDS instance having CPU utilization below defined threshold within last 7 days (idle instance).',
    more_info: 'Idle Amazon RDS instance represent a good candidate to reduce your monthly AWS costs and avoid accumulating unnecessary usage charges.',
    link: 'https://aws.amazon.com/rds/features/',
    recommended_action: 'Identify and remove idle RDS instance',
    apis: ['RDS:describeDBInstances', 'CloudWatch:getRdsMetricStatistics', 'CloudWatch:getRdsWriteIOPSMetricStatistics', 'CloudWatch:getRdsReadIOPSMetricStatistics'],
    settings: {
        rds_idle_instance_cpu_percentage: {
            name: 'RDS Idle Instance Average CPU Usage Percentage',
            description: 'Return a failing result when consumed RDS insatnce cpu threshold equals or less this percentage',
            regex: '^(100|[1-9][0-9]?)$', 
            default: '1.0'
        },
        rds_idle_instance_readIOPS_percentage: {
            name: 'RDS Idle Instance Average Read IOPS Percentage',
            description: 'Return a failing result when consumed RDS insatnce read IOPS threshold equals or less this percentage',
            regex: '^(100|[1-9][0-9]?)$', 
            default: '20'
        },
        rds_idle_instance_writeIOPS_percentage: {
            name: 'RDS Idle Instance Average Write IOPS Percentage',
            description: 'Return a failing result when consumed RDS insatnce write IOPS threshold equals or less this percentage',
            regex: '^(100|[1-9][0-9]?)$', 
            default: '20'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var rds_idle_instance_cpu_percentage = settings.rds_idle_instance_cpu_percentage || this.settings.rds_idle_instance_cpu_percentage.default; 
        var rds_idle_instance_readIOPS_percentage = settings.rds_idle_instance_readIOPS_percentage || this.settings.rds_idle_instance_readIOPS_percentage.default;
        var rds_idle_instance_writeIOPS_percentage = settings.rds_idle_instance_writeIOPS_percentage || this.settings.rds_idle_instance_writeIOPS_percentage.default;
        rds_idle_instance_cpu_percentage = parseFloat(rds_idle_instance_cpu_percentage);

        async.each(regions.rds, function(region, rcb) {
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for RDS instance: ${helpers.addError(describeDBInstances)}`, region);
                return rcb();
            }

            if (!describeDBInstances.data.length){
                helpers.addResult(results, 0, 'No RDS instance found', region);
                return rcb();
            }

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn) return;
           
                var getRdsMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getRdsMetricStatistics', region, instance.DBInstanceIdentifier]);
                var getRdsReadIOPSMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getRdsReadIOPSMetricStatistics', region, instance.DBInstanceIdentifier]);
                var getRdsWriteIOPSMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getRdsWriteIOPSMetricStatistics', region, instance.DBInstanceIdentifier]);

                if (!getRdsMetricStatistics || getRdsMetricStatistics.err ||
                    !getRdsMetricStatistics.data || !getRdsMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3,`Unable to query for CPU metric statistics: ${helpers.addError(getRdsMetricStatistics)}`, region, resource);
                    return;
                }

                if (!getRdsMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0,'CPU metric statistics are not available', region, resource);
                }
                   
                   
                if (!getRdsReadIOPSMetricStatistics || getRdsReadIOPSMetricStatistics.err ||
                        !getRdsReadIOPSMetricStatistics.data || !getRdsReadIOPSMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3, `Unable to query for Read IOPS metric statistics: ${helpers.addError(getRdsReadIOPSMetricStatistics)}`, region, resource);
                    return;
                }
    
                if (!getRdsReadIOPSMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0, 'Read IOPS metric statistics are not available', region, resource);
                }
                        
                if (!getRdsWriteIOPSMetricStatistics || getRdsWriteIOPSMetricStatistics.err ||
                            !getRdsWriteIOPSMetricStatistics.data || !getRdsWriteIOPSMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3,`Unable to query for Write IOPS metric statistics: ${helpers.addError(getRdsWriteIOPSMetricStatistics)}`, region, resource);
                    return;
                }
        
                if (!getRdsWriteIOPSMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0,'Write IOPS metric statistics are not available', region, resource);
                }
                var cpuIdle = false;
                var readIopsIdle = false;
                var writeIopsIdle = false;
                // Check CPU utilization
                if (getRdsMetricStatistics.data.Datapoints.every(datapoint => datapoint.Average <= rds_idle_instance_cpu_percentage)) {
                    cpuIdle = true;
                }
                // Check Read IOPS
                if (getRdsReadIOPSMetricStatistics.data.Datapoints.every(datapoint => datapoint.Sum <= rds_idle_instance_readIOPS_percentage)) {
                    readIopsIdle = true;
                }
                // Check Write IOPS
                if (getRdsWriteIOPSMetricStatistics.data.Datapoints.every(datapoint => datapoint.Sum <= rds_idle_instance_writeIOPS_percentage)) {
                    writeIopsIdle = true;
                }
                if (cpuIdle || readIopsIdle || writeIopsIdle) {
                    helpers.addResult(results, 2, 'RDS instance is idle', region, instance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 0, 'RDS instance is not idle', region, instance.DBInstanceArn);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }   
};
