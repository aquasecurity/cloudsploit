var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Neptune Database Multiple AZ',
    category: 'Neptune',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that your AWS Neptune database instances are created to be cross-AZ for high availability.',
    more_info: '',
    recommended_action: 'Modify Neptune database instance to enable scaling across multiple availability zones.',
    link: '',
    apis: ['Neptune:describeDBClusters'],
    realtime_triggers: ['neptune:CreateDBCluster', 'neptune:DeleteDBCluster'], 

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

                if (cluster.MultiAZ) {
                    helpers.addResult(results, 0, 'Neptune database instance has multi-AZ enabled', resource, region); 
                } else {
                    helpers.addResult(results, 2, 'Neptune database instance does not have multi-AZ enabled', resource, region);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
