var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database IAM Authentication Enabled',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that AWS Neptune database instance has IAM database authentication feature enabled.',
    more_info: 'Enabling IAM authentication for AWS Neptune adds an extra layer of security by allowing access control through IAM credentials. It ensures that network traffic for clusters is encrypted using SSL and allows centralized management. All authentication requests are automatically signed with a secure access key instead of using a password.',
    recommended_action: 'Modify Neptune database instance and enable IAM database authentication.',
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
                if (!cluster.DBClusterArn || cluster.Engine !== 'neptune') continue;

                if (cluster.IAMDatabaseAuthenticationEnabled) {
                    helpers.addResult(results, 0, 'Neptune database instance has IAM authentication enabled', region, cluster.DBClusterArn); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have IAM authentication enabled', region, cluster.DBClusterArn);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
