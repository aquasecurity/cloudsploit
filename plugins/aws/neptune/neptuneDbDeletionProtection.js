var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Deletion Protection Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that AWS Neptune database instances have deletion protection feature enabled.',
    more_info: 'Enabling deletion protection feature for Amazon Neptune adds an extra layer of security, preventing accidental database deletions or deletion by an unauthorized user. A Neptune DB cluster can\'t be deleted while deletion protection is enabled which ensures continuous availability of data.',
    recommended_action: 'Modify Neptune database instance and enable deletion protection.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/manage-console-instances-delete.html',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster', 'neptune:DeleteDBCluster', 'neptune:ModifyDBCluster'], 

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
                if (!cluster.DBClusterArn || cluster.Engine != 'neptune') continue;
                if (cluster.DeletionProtection) {
                    helpers.addResult(results, 0, 'Neptune database instance has deletion protection enabled', region, cluster.DBClusterArn); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance has deletion protection disabled', region, cluster.DBClusterArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};