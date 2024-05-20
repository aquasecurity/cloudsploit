var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Minor Version Upgrade',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures Auto Minor version upgrade is enabled on Neptune database instances.',
    more_info: 'AWS Neptune database service releases engine version upgrades regularly to introduce software features, bug fixes, security patches and performance improvements. Enabling auto minor version upgrade feature ensures that minor engine upgrades are applied automatically to the instance during the maintenance window.',
    recommended_action: 'Modify Neptune database instance and enable automatic minor version upgrades feature.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/cluster-maintenance.html',
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
                if (!cluster.DBClusterArn) continue;

                if (cluster.AutoMinorVersionUpgrade) {
                    helpers.addResult(results, 0, 'Neptune database instance has auto minor version upgrade enabled', cluster.DBClusterArn, region); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have auto minor version upgrade enabled', cluster.DBClusterArn, region);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};