var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database IAM Authentication Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that AWS Neptune database instance has IAM database authentication feature enabled.',
    more_info: 'Enabling IAM authentication for AWS Neptune adds an extra layer of security by allowing access control through IAM credentials, providing more precise control over who can access your Neptune resources.',
    recommended_action: 'Modify Neptune database instance to enable IAM database authentication.',
    link: 'https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster', 'neptune:DeleteDBCluster','neptune:ModifyDBCluster'], 

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

                if (cluster.IAMDatabaseAuthenticationEnabled) {
                    helpers.addResult(results, 0, 'Neptune database instance has IAM authentication enabled', resource, region); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have IAM authentication enabled', resource, region);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
