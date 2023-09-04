var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'RDS Default Port',
    category: 'RDS',
    domain: 'Databases',
    description: 'Ensure RDS database instances are not using the default ports.',
    more_info: 'Running RDS instances on default ports represent a potential security concern. Moving RDS instances ports to non-default ports will add an extra layer of security, protecting publicly accessible AWS RDS databases from brute force and dictionary attacks.',
    link: 'https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_CommonTasks.Connect.html',
    recommended_action: 'Change the default port number of the RDS instance to non-default port.',
    apis: ['RDS:describeDBInstances'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultPorts = [
            { 'engine': 'aurora-mysql', 'port': 3306 },
            { 'engine': 'aurora-postgresql', 'port': 5432 },
            { 'engine': 'custom-oracle-ee', 'port': 1521 },
            { 'engine': 'mariadb', 'port': 3306 },
            { 'engine': 'mysql', 'port': 3306 },
            { 'engine': 'oracle-ee', 'port': 1521 },
            { 'engine': 'oracle-ee-cdb', 'port': 1521 },
            { 'engine': 'oracle-se2', 'port': 1521 },
            { 'engine': 'oracle-se2-cdb', 'port': 1521 },
            { 'engine': 'postgres', 'port': 5432 },
            { 'engine': 'sqlserver-ee', 'port': 1433 },
            { 'engine': 'sqlserver-se', 'port': 1433 },
            { 'engine': 'sqlserver-ex', 'port': 1433 },
            { 'engine': 'sqlserver-web', 'port': 1433 }
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
                    return d.engine == instance.Engine && d.port == instance.Endpoint.Port;
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