var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Instance Default Master Username',
    category: 'RDS',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures RDS instance does not have a default master username',
    more_info: 'By default, RDS uses the default master username which has the maximum permissions for your instance. RDS instances should be configured to use unique username to ensure security.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_CreateDBInstance.html',
    recommended_action: 'Create a new RDS instance with the desired username, and migrate the database to the new instance.',
    apis: ['RDS:describeDBInstances'],
    realtime_triggers: ['rds:CreateDBInstance', 'rds:RestoreDBInstanceFromDBSnapshot', 'rds:RestoreDBInstanceFromS3','rds:DeleteDBInstance'],  

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

            var defaultusername = ['admin','postgres'];

            describeDBInstances.data.forEach(instance => {
                if (!instance.DBInstanceArn || !instance.MasterUsername) return;

                if (defaultusername.includes(instance.MasterUsername)) {
                    helpers.addResult(results, 2, 'RDS instance has a default master username',
                        region, instance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 0, 'RDS instance does not have a default master username',
                        region, instance.DBInstanceArn);
                }
            });
       
            rcb();
        },function(){
            callback(null, results, source);
        });
    }  
};


