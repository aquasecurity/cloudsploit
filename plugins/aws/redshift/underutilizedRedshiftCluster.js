var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Underutilized Redshift Cluster Check',
    category: 'Redshift',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure Redshift clusters are not underutilized',
    more_info: 'Underutilized clusters are good candidates to reduce your monthly AWS costs and avoid accumulating unnecessary usage charges.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/metrics-listing.html#redshift-metrics',
    recommended_action: 'Resize the underused Redshift cluster to optimize costs and resource utilization.',
    apis: ['Redshift:describeClusters', 'CloudWatch:getredshiftMetricStatistics', 'STS:getCallerIdentity'],
    settings: {
        redshift_cluster_cpu_threshold: {
            name: 'Redshift CPU Threshold',
            description: 'The CPU utilization threshold in percentage below which a cluster is considered underutilized.',
            regex: '^(100|[1-9][0-9]?)$',
            default: '5'
        }
    },
    realtime_triggers: ['redshift:CreateCluster','redshift:CreateClusterSnapshot', 'redshift:RestoreFromClusterSnapshot','redshift:DeleteCluster'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var cpuThreshold = settings.redshift_cluster_cpu_threshold || this.settings.redshift_cluster_cpu_threshold.default;

        async.each(regions.redshift, function(region, rcb) {
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            if (!describeClusters) return rcb();
            
            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            describeClusters.data.forEach(cluster => {
                if (!cluster.ClusterIdentifier) return;

                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${cluster.clusterIdentifier}`;

                var getMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getredshiftMetricStatistics', region, cluster.ClusterIdentifier]);

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
                    var utilizationCount = 0;

                    for (var i = cpuDatapoints.length - 1; i >= 0; i--) {
                        if (cpuDatapoints[i].Average < cpuThreshold) {
                            utilizationCount++;
                        }
                    }
    
                    var utilizationPercentage = (utilizationCount / cpuDatapoints.length) * 100;
    
                    if (utilizationPercentage >= 99) {
                        helpers.addResult(results, 2,
                            `Redshift cluster has had less than ${cpuThreshold} cluster-wide average CPU utilization for 99% of the last 7 days`, region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'Redshift cluster is not underutilized', region, resource);
                    }
                }
            });
            
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
