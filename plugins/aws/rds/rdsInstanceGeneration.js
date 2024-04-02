var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Instance Generation',
    category: 'RDS',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that AWS RDS instance is not using older generation of EC2',
    more_info: 'Amazon RDS instances running on older generation EC2 instances may not have access to the latest hardware capabilities and performance improvements. It is recommended to upgrade the RDS instance to its latest generation for optimal performance and security.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Concepts.DBInstanceClass.html',
    recommended_action: 'Upgrade the instance to its latest generation.',
    apis: ['RDS:describeDBInstances'],
    realtime_triggers: ['rds:CreateDBInstance', 'rds:ModifyDBInstance', 'rds:RestoreDBInstanceFromDBSnapshot', 'rds:RestoreDBInstanceFromS3','rds:DeleteDBInstance'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var olderGenerations = [
            'db.t1.micro',
            'db.m1.small',
            'db.m1.medium',
            'db.m1.large',
            'db.m1.xlarge',
            'db.m2.xlarge',
            'db.m2.2xlarge',
            'db.m2.4xlarge'
        ];

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
            
            describeDBInstances.data.forEach(function(Rds){
                var dbInstanceClass = Rds.DBInstanceClass;

                if (olderGenerations.includes(dbInstanceClass)){
                    helpers.addResult(results, 2, 'RDS instance is using an older generation of EC2: ' + dbInstanceClass, region, Rds.DBInstanceArn);
                } else { 
                    helpers.addResult(results, 0, 'RDS instance is using current generation of EC2: ' + dbInstanceClass, region, Rds.DBInstanceArn);
                }
            });

            rcb();    
        },function() {
            callback(null, results, source);
        });
    }
};