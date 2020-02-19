var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Database SSL Enabled',
    category: 'SQL',
    description: 'Ensures SQL databases have SSL enabled',
    more_info: 'Enabling SSL ensures that the sensitive data being transferred from the database is encrypted.',
    link: 'https://cloud.google.com/sql/docs/mysql/instance-settings',
    recommended_action: 'Ensure that SSL is enabled on all SQL databases.',
    apis: ['instances:sql:list'],
    compliance: {
        pci: 'PCI requires strong cryptographic and security protocols ' +
             'when transmitting user data, this includes using SSL.',
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'Database SSL should be used to ensure SQL databases ' +
            'are always connecting through secure encryption.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.instances.sql, function(region, rcb){
            let sqlInstances = helpers.addSource(cache, source,
                ['instances', 'sql', 'list', region]);

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
                if (sqlInstance.settings &&
                    sqlInstance.settings.ipConfiguration &&
                    sqlInstance.settings.ipConfiguration.requireSsl) {
                    helpers.addResult(results, 0,
                        'SQL database has SSL enabled', region, sqlInstance.name);
                } else {
                    helpers.addResult(results, 2,
                        'SQL database has SSL disabled', region, sqlInstance.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}