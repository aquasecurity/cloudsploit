var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL No Public IPs',
    category: 'SQL',
    description: 'Ensure that SQL instances are using private IPs instead of public IPs.',
    more_info: 'Cloud SQL databases should always use private IP addresses which provide improved network security and lower latency.',
    link: 'https://cloud.google.com/sql/docs/mysql/configure-private-ip',
    recommended_action: 'Make sure that SQL databases IP addresses setting does not have IP address of PRIMARY type',
    apis: ['instances:sql:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        
        async.each(regions.instances.sql, function(region, rcb) {
            let sqlInstances = helpers.addSource(
                cache, source, ['instances', 'sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === "READ_REPLICA_INSTANCE") return;

                if (sqlInstance.ipAddresses &&
                    sqlInstance.ipAddresses.length) {
                        let found = sqlInstance.ipAddresses.find(address => address.type.toUpperCase() == 'PRIMARY');

                        if (found) {
                            helpers.addResult(results, 2, 
                                'SQL instance has public IPs', region, sqlInstance.name);
                        } else {
                            helpers.addResult(results, 0,
                                'SQL instance does not have public IPs', region, sqlInstance.name);
                        }
                } else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have public IPs', region, sqlInstance.name);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
} 
