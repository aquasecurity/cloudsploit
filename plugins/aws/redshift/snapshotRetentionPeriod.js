var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Automated Snapshot Retention Period',
    category: 'Redshift',
    description: 'Ensures that retention period is set for Amazon Redshift automated snapshots.',
    more_info: 'Amazon Redshift clusters should have retention period set for automated snapshots for data protection and to avoid unexpected failures.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-snapshots.html',
    recommended_action: 'Modify Amazon Redshift cluster to set snapshot retention period',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

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

            describeClusters.data.forEach(cluster => {
                if (!cluster.ClusterIdentifier) return;

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;

                if (cluster.AutomatedSnapshotRetentionPeriod && cluster.AutomatedSnapshotRetentionPeriod > 0) {
                    helpers.addResult(results, 0,
                        'Redshift cluster has retention period set', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Redshift cluster does not have retention period set', region, resource);
                }
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
