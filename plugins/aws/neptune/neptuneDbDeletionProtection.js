var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Deletion Protection Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that your AWS Neptune database instance has deletion protection feature enabled.',
    more_info: 'Enabling deletion protection for AWS Neptune adds an extra layer of security, preventing accidental deletions and ensuring the continued availability and integrity of your valuable data.',
    recommended_action: 'Modify Neptune database instance and enable deletion protection.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-instances-delete.html',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster', 'neptune:DeleteDBCluster','neptune:UpdateCluster'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);


        async.each(regions.neptune, function(region, rcb){
            var describeDBClusters = helpers.addSource(cache, source,
                ['neptune', 'describeDBClusters', region]);

            if (!describeDBClusters) return rcb();

            if (describeDBClusters.err || !describeDBClusters.data) {
                helpers.addResult(results, 3,
                    `Unable to list Neptune database instances: ${helpers.addError(describeDBClusters)}`, region);
                return rcb();
            }

            if (!describeDBClusters.data.length) {
                helpers.addResult(results, 0,
                    'No Neptune database instances found', region);
                return rcb();
            }

            for (let cluster of describeDBClusters.data) {
                if (!cluster.DBClusterArn) continue;

                let resource = cluster.DBClusterArn;

                if (cluster.DeletionProtection) {
                    helpers.addResult(results, 0, 'Neptune database instance has deletion protection enabled', resource, region); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have deletion protection enabled', resource, region);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
