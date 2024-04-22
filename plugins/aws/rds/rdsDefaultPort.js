var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Default Port',
    category: 'RDS',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure RDS database instances are not using the default ports.',
    more_info: 'Using default ports for running RDS instances can be a security risk. To protect publicly accessible RDS databases from brute force and dictionary attacks and add an additional layer of security, shift RDS instance ports to non-default ones.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html',
    recommended_action: 'Change the default port number of the RDS instance to non-default port.',
    apis: ['RDS:describeDBInstances'],
    realtime_triggers: ['rds:CreateDBInstance', 'rds:ModifyDBInstance', 'rds:RestoreDBInstanceFromDBSnapshot', 'rds:RestoreDBInstanceFromS3','rds:DeleteDBInstance'],  

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultPorts = [
            { 'engine': 'mariadb', 'port': 3306 },
            { 'engine': 'mysql', 'port': 3306 },
            { 'engine': 'oracle', 'port': 1521 },
            { 'engine': 'postgres', 'port': 5432 },
            { 'engine': 'sqlserver', 'port': 1433 },
        ];

        async.each(regions.rds, function(region, rcb){
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

            for (var instance of describeDBInstances.data) {
                if (!instance.DBInstanceArn || !instance.Engine ||
                    !(instance.Endpoint && instance.Endpoint.Port)) continue;
                var defaultPort = defaultPorts.filter((d) => {
                    return instance.Engine.toLowerCase().includes(d.engine) && d.port == instance.Endpoint.Port;
                });

                if (defaultPort && defaultPort.length) {
                    helpers.addResult(results, 2, 'RDS instance is running on default port',
                        region, instance.DBInstanceArn);
                } else {
                    helpers.addResult(results, 0, 'RDS instance is not running on default port',
                        region, instance.DBInstanceArn);
                }
            }
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
