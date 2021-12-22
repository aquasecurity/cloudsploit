const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enable Geo-Redundant Backups',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensure that your Microsoft Azure PostgreSQL database servers have geo-redundant backups enabled.',
    more_info: 'Enabling geo-redundant backup storage for PostgreSQL database servers gives better protection and ability to restore your server in a different region in the event of a disaster.',
    recommended_action: 'PostgreSQL servers does not support modifying geo-redundant storage configuration. ' +
        'You need to create a new server using current server\'s configuration with geo-redundant backup storage enabled ' +
        'and then delete the current PostgreSQL server',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/concepts-backup',
    apis: ['servers:listPostgres'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let postgresServer of servers.data) {
                if (postgresServer.storageProfile &&
                    postgresServer.storageProfile.geoRedundantBackup &&
                    postgresServer.storageProfile.geoRedundantBackup.toUpperCase() === 'ENABLED') {
                    helpers.addResult(results, 0,
                        'The PostgreSQL Server has geo-redundant backup storage enabled', location, postgresServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'The PostgreSQL Server does not have geo-redundant backup storage enabled', location, postgresServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
