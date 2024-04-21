const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Encryption At Rest with BYOK',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that Azure PostgreSQL Database Servers data is encrypted with CMK.',
    more_info: 'Data at rest encryption with BYOK ensures that your PostgreSQL server data is protected using a key that you manage. Enabling BYOK adds an extra layer of security by allowing you to control access to the encryption keys.',
    recommended_action: 'Enable CMK encryotion for PostgreSQL database servers.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/single-server/concepts-data-encryption-postgresql',
    apis: ['servers:listPostgres'],
    realtime_triggers: ['microsoftdbforpostgresql:servers:write','microsoftdbforpostgresql:servers:delete'],

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
                    'Unable to query for PostgreSQL Servers:' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let server of servers.data) {
                if (!server.id) continue;

                if (server.byokEnforcement && server.byokEnforcement.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 0, 'PostgreSQL server is encrypted using CMK', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL server is not encrypted using CMK', location, server.id);
                }
            }
           
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
