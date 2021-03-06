var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Redshift User Activity Logging Enabled',
    category: 'Redshift',
    description: 'Ensure that user activity logging is enabled for your Amazon Redshift clusters.',
    more_info: 'Redshift clusters associated parameter groups should have user activity logging enabled in order to log user activities performed.',
    link: 'https://docs.aws.amazon.com/redshift/latest/mgmt/db-auditing.html#db-auditing-enable-logging',
    recommended_action: 'Update Redshift parameter groups to enable user activity logging',
    apis: ['Redshift:describeClusters', 'Redshift:describeClusterParameterGroups', 'Redshift:describeClusterParameters', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.redshift, function(region, rcb){
            var describeClusters = helpers.addSource(cache, source,
                ['redshift', 'describeClusters', region]);

            var describeClusterParameterGroups = helpers.addSource(cache, source,
                ['redshift', 'describeClusterParameterGroups', region]);

            if (!describeClusters) return rcb();

            if (describeClusters.err || !describeClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Redshift clusters: ${helpers.addError(describeClusters)}`, region);
                return rcb();
            }

            if (!describeClusters.data.length) {
                helpers.addResult(results, 0,
                    'No Redshift clusters found', region);
                return rcb();
            }

            if (!describeClusterParameterGroups || describeClusterParameterGroups.err || !describeClusterParameterGroups.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Redshift cluster parameter groups: ${helpers.addError(describeClusterParameterGroups)}`, region);
                return rcb();
            }
            
            async.each(describeClusters.data, function(cluster, ccb){
                if (!cluster.ClusterIdentifier) return ccb();

                var clusterIdentifier = cluster.ClusterIdentifier;
                var resource = `arn:${awsOrGov}:redshift:${region}:${accountId}:cluster:${clusterIdentifier}`;
                var loggingEnabled = false;

                if (cluster.ClusterParameterGroups.length) {
                    for (var cg in cluster.ClusterParameterGroups) {
                        var clusterParameterGroup = cluster.ClusterParameterGroups[cg];

                        if (!clusterParameterGroup.ParameterGroupName) continue;

                        var groupName = clusterParameterGroup.ParameterGroupName;

                        if (!groupName.startsWith('default.redshift')) {
                            var describeClusterParameters = helpers.addSource(cache, source,
                                ['redshift', 'describeClusterParameters', region, groupName]);
        
                            if (!describeClusterParameters ||
                                describeClusterParameters.err ||
                                !describeClusterParameters.data ||
                                !describeClusterParameters.data.Parameters) {
                                helpers.addResult(results, 3,
                                    `Unable to query parameter group "${groupName}": ${helpers.addError(describeClusterParameters)}`, 
                                    region, resource);
                                return ccb();
                            }
        
                            for (var p in describeClusterParameters.data.Parameters) {
                                var param = describeClusterParameters.data.Parameters[p];
        
                                if (param.ParameterName && param.ParameterName === 'enable_user_activity_logging' &&
                                    param.ParameterValue && param.ParameterValue === 'true') {
                                    loggingEnabled = true;
                                    break;
                                }
                            }
                        }

                        if(loggingEnabled) break;
                    }
                }
                
                if (loggingEnabled) {
                    helpers.addResult(results, 0,
                        `Parameter group associated with Redshift cluster "${clusterIdentifier}" has user logging enabled`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `Parameter group associated with Redshift cluster "${clusterIdentifier}" does not have user logging enabled`,
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
