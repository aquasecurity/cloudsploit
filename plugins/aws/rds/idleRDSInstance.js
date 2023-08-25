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
    apis: ['RDS:describeDBInstances', 'CloudWatch:getRdsMetricStatistics'],
    settings: {
        rds_idle_instance_percentage: {
            name: 'RDS Idle Instance Average Percentage',
            description: 'Return a failing result when consumed RDS insatnce cpu threshold equals or less this percentage',
            regex: '^(100|[1-9][0-9]?)$', 
            default: '1.0'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var rds_idle_instance_percentage = settings.rds_idle_instance_percentage || this.settings.rds_idle_instance_percentage.default; 

        if (!rds_idle_instance_percentage.length) return callback(null, results, source);

        rds_idle_instance_percentage = parseFloat(rds_idle_instance_percentage);

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

                var resource = instance.DBInstanceArn;             
                var getRdsMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getRdsMetricStatistics', region, instance.DBInstanceIdentifier]);
               
                if (!getRdsMetricStatistics || getRdsMetricStatistics.err ||
                    !getRdsMetricStatistics.data || !getRdsMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3,
                        `Unable to query for CPU metric statistics: ${helpers.addError(getRdsMetricStatistics)}`, region, resource);
                    return;
                }

                if (!getRdsMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0,
                        'CPU metric statistics are not available', region, resource);
                } else {
                    const isIdle = getRdsMetricStatistics.data.Datapoints.every(datapoint => datapoint.Average >= rds_idle_instance_percentage);
                    if (!isIdle) {
                        helpers.addResult(results, 2,
                            'RDS instance is idle', region, instance.DBInstanceArn);
                    } else {
                        helpers.addResult(results, 0,
                            'RDS instance is not idle', region, instance.DBInstanceArn);
                    }           
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }   
};
