var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Underutilized Redshift Cluster Check',
    category: 'Redshift',
    domain: 'Databases',
    description: 'Ensure Redshift clusters are not underutilized',
    more_info: 'Underutilized clusters are good canidates to reduce your monthly AWS costs and avoid accumulating unnecessary usage charges.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/managing-cluster-usage-limits.html',
    recommended_action: 'Downsizing underused AWS Redshift clusters to meet the capacity needs at the lowest cost represents an efficient strategy to reduce your monthly AWS costs.',
    apis: ['Redshift:describeClusters', 'CloudWatch:getredshiftMetricStatistics', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var cpuThreshold = 5; 

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
                            'Redshift cluster has had less than 5% cluster-wide average CPU utilization for 99% of the last 7 days', region, resource);
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