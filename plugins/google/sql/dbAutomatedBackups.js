var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Automated Backups',
    category: 'SQL',
    description: 'Ensures automated backups are enabled for SQL instances',
    more_info: 'Google provides a simple method of backing up SQL instances at a regular interval. This should be enabled to provide an option for restoring data in the event of a database compromise or hardware failure.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure that all database instances are configured with automatic backups enabled.',
    apis: ['instances:sql:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb){
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
                if (sqlInstance.instanceType != "READ_REPLICA_INSTANCE" &&
                    sqlInstance.settings &&
                    sqlInstance.settings.backupConfiguration &&
                    sqlInstance.settings.backupConfiguration.enabled) {
                    helpers.addResult(results, 0, 
                        'Automated backups are enabled', region, sqlInstance.name);
                } else if (sqlInstance.instanceType == "READ_REPLICA_INSTANCE"){
                } else {
                    helpers.addResult(results, 2, 
                        'Automated backups are not enabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}