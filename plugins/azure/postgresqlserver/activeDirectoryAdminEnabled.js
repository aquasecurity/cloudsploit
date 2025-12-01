const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Entra ID Admin Configured',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that Entra ID admin is set up on all PostgreSQL servers.',
    more_info: 'Using Azure Entra ID authentication allows key rotation and permission management to be managed in one location for all servers. This can be done are configuring an Entra ID administrator.',
    recommended_action: 'Set up an Entra ID admin for PostgreSQL database servers.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/howto-configure-sign-in-aad-authentication',
    apis: ['servers:listPostgres', 'serverAdministrators:list'],
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
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let postgresServer of servers.data) {
                const serverAdministrators = helpers.addSource(cache, source,
                    ['serverAdministrators', 'list', location, postgresServer.id]);
                
                if (!serverAdministrators || serverAdministrators.err || !serverAdministrators.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Entra ID admins: ' + helpers.addError(serverAdministrators), location, postgresServer.id);
                } else {
                    if (!serverAdministrators.data.length) {
                        helpers.addResult(results, 2, 'No Entra ID admin found for the server', location, postgresServer.id);
                    } else {
                        var entraIdAdminEnabled = false;
                        serverAdministrators.data.forEach(serverAdministrator => {
                            if (serverAdministrator.name &&
                                serverAdministrator.name.toLowerCase() === 'activedirectory') {
                                entraIdAdminEnabled = true;
                            }
                        });

                        if (entraIdAdminEnabled) {
                            helpers.addResult(results, 0,
                                'Entra ID admin is enabled on the PostgreSQL server', location, postgresServer.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Entra ID admin is not enabled on the PostgreSQL server', location, postgresServer.id);
                        }
                    }
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
