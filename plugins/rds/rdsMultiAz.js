var async = require('async');
var helpers = require('../../helpers');

module.exports = {
    title: 'RDS Multiple AZ',
    category: 'RDS',
    description: 'Ensures that RDS instances are created to be cross-AZ for high availability.',
    more_info: 'Creating RDS instances in a single AZ creates a single point of failure for all systems relying on that database. All RDS instances should be created in multiple AZs to ensure proper failover.',
    link: 'http://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.MultiAZ.html',
    recommended_action: 'Modify the RDS instance to enable scaling across multiple availability zones.',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, callback) {
        var results = [];
        var source = {};

        async.each(helpers.regions.rds, function(region, rcb){
            var describeDBInstances = helpers.addSource(cache, source,
                ['rds', 'describeDBInstances', region]);

            if (!describeDBInstances) return rcb();

            if (describeDBInstances.err || !describeDBInstances.data) {
                helpers.addResult(results, 3,
                    'Unable to query for RDS instances: ' + helpers.addError(describeDBInstances), region);
                return rcb();
            }

            if (!describeDBInstances.data.length) {
                helpers.addResult(results, 0, 'No RDS instances found', region);
                return rcb();
            }

            // loop through Rds Instances
            describeDBInstances.data.forEach(function(Rds){
                if (Rds.MultiAZ){
                    helpers.addResult(results, 0,
                        'RDS instance has multi-AZ enabled',
                        region, Rds.DBInstanceArn);
                } else {
                    helpers.addResult(results, 2,
                        'RDS instance does not have multi-AZ enabled',
                        region, Rds.DBInstanceArn);
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
