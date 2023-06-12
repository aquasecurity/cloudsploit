var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Underutilized Redshift Cluster Check',
    category: 'Redshift',
    domain: 'Databases',
    description: 'Identify Redshift clusters that appear to be underutilized',
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


        var idleCpuThreshold = 5; 
        var idleDurationThreshold = 99; 

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

                //var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                    var getMetricStatistics = helpers.addSource(cache, source,
                        ['cloudwatch', 'getredshift2MetricStatistics', region, cluster.clusterIdentifier]);

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
                        // var cpuDatapoints = getMetricStatistics.data.Datapoints;
                        // var cpuUtilization = cpuDatapoints[cpuDatapoints.length - 1].Average;
                        // if (cpuUtilization > cpuThreshold) {
                        //     helpers.addResult(results, 2,
                        //         `CPU threshold exceeded - Current CPU utilization: ${cpuUtilization}%`, region, resource);
                        // } else {
                        //     helpers.addResult(results, 0,
                        //         `CPU threshold not exceeded - Current CPU utilization: ${cpuUtilization}%`, region, resource);
                        // }
                    }
                });
            

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};