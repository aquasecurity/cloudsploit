var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster Audit Logging Enabled',
    category: 'Redshift',
    description: 'Ensure audit logging is enabled for Redshift clusters for security and troubleshooting purposes.',
    more_info: 'Redshift clusters should be configured to enable audit logging to log cluster usage information.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing-console.html',
    recommended_action: 'Modify Redshift clusters to enable audit logging',
    apis: ['Redshift:describeClusters', 'Redshift:describeLoggingStatus', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0, 'No Redshift clusters found', region);
                return rcb();
            }

            async.each(describeClusters.data, function(cluster, ccb){
                if (!cluster.ClusterIdentifier) return ccb();

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                var describeLoggingStatus = helpers.addSource(cache, settings,
                    ['redshift', 'describeLoggingStatus', region, clusterIdentifier]);

                if (!describeLoggingStatus ||
                    describeLoggingStatus.err ||
                    !describeLoggingStatus.data) {
                    helpers.addResult(results, 3,
                        `Unable to describe logging status for cluster "${clusterIdentifier}": ${helpers.addError(describeLoggingStatus)}`,
                        region, resource);
                }

                if (describeLoggingStatus.data.LoggingEnabled &&
                    describeLoggingStatus.data.LoggingEnabled === true) {
                    helpers.addResult(results, 0,
                        `Redshift cluster "${clusterIdentifier}" has audit logging enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Redshift cluster "${clusterIdentifier}" does not have audit logging enabled`,
                        region, resource);
                }

                ccb();
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
