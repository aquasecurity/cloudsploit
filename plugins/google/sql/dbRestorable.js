var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'DB Restorable',
    category: 'SQL',
    description: 'Ensures SQL instances can be restored to a recent point',
    more_info: 'Google will maintain a point to which the database can be restored. This point should not drift too far into the past, or else the risk of irrecoverable data loss may occur.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure all database instances are configured with automatic backups and can be restored to a recent point with binary logging enabled.',
    apis: ['instances:sql:list', 'backupRuns:list'],
    compliance: {
        pci: 'PCI requires that security procedures, including restoration of ' +
             'compromised services, be tested frequently. RDS restorable time ' +
             'indicates the last known time to which the instance can be restored.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb){
            let sqlInstances = helpers.addSource(
                cache, source, ['instances', 'sql', 'list', region]);
            let backupRuns = helpers.addSource(
                cache, source, ['backupRuns', 'list', region]);
            
            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region, null, null, sqlInstances.err);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            if (!backupRuns || backupRuns.err || !backupRuns.data) {
                helpers.addResult(results, 3,
                    `Unable to query SQL backup runs: ${helpers.addError(backupRuns)}`, region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                let found = backupRuns.data.find(backup => backup.instance && sqlInstance.name && backup.instance == sqlInstance.name);
                
                if (found) {
                    helpers.addResult(results, 0, 
                        'SQL instance has backup available', region, sqlInstance.name);
                }
                else {
                    helpers.addResult(results, 2, 
                        'SQL instance does not have backups available', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
