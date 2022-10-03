var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Instance Has Tags',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure that AWS RDS instance have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_Tagging.html',
    recommended_action: 'Modify the RDS instance to add tags.',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.rds, function(region, rcb) {
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

            for ( var rdsInstance of describeDBInstances.data){
                if (!rdsInstance.TagList || !rdsInstance.TagList.length){
                    helpers.addResult(results, 2, 'RDS instance does not have any tags',
                        region, rdsInstance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 0, 'RDS instance has tags', region, rdsInstance.DBInstanceArn);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
