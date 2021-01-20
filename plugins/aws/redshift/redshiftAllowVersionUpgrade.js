var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift Cluster Allow Version Upgrade',
    category: 'Redshift',
    description: 'Ensure that version upgrade is enabled for Redshift clusters to automatically receive upgrades during the maintenance window.',
    more_info: 'Redshift clusters should be configured to allow version upgrades to get the newest features, bug fixes or the latest security patches released.',
    link: 'https://docs.amazonaws.cn/en_us/redshift/latest/mgmt/redshift-mgmt.pdf',
    recommended_action: 'Modify Redshift clusters to allow version upgrade',
    apis: ['Redshift:describeClusters', 'STS:getCallerIdentity'],

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

                if (cluster.AllowVersionUpgrade) {
                    helpers.addResult(results, 0,
                        `Redshift cluster "${clusterIdentifier}" is configured to allow version upgrade`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Redshift cluster "${clusterIdentifier}" is not configured to allow version upgrade`,
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
