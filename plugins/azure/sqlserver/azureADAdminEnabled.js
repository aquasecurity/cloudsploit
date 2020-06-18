var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Active Directory Admin Enabled',
    category: 'SQL Server',
    description: 'Ensures that Active Directory admin is enabled on all SQL servers.',
    more_info: 'Enabling Active Directory admin allows users to manage account admins in a central location, allowing key rotation and permission management to be managed in one location for all servers and databases.',
    recommended_action: 'Ensure Azure Active Directory admin is enabled on all SQL servers.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure',
    apis: ['servers:listSql', 'serverAzureADAdministrators:listByServer'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            var servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const serverAzureADAdministrators = helpers.addSource(cache, source,
                    ['serverAzureADAdministrators', 'listByServer', location, server.id]);

                if (!serverAzureADAdministrators || serverAzureADAdministrators.err || !serverAzureADAdministrators.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for Active Directory admins: ' + helpers.addError(serverAzureADAdministrators), location, server.id);
                } else {
                    if (!serverAzureADAdministrators.data.length) {
                        helpers.addResult(results, 2, 'Active Directory admin is not enabled on the server', location, server.id);
                    } else {
                        var adAdminEnabled = false;
                        serverAzureADAdministrators.data.forEach(serverAzureADAdministrator => {
                            if (serverAzureADAdministrator.name &&
                                serverAzureADAdministrator.name.toLowerCase() === 'activedirectory') {
                                adAdminEnabled = true;
                            }
                        });

                        if (adAdminEnabled) {
                            helpers.addResult(results, 0,
                                'Active Directory admin is enabled on the SQL server', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Active Directory admin is not enabled on the SQL server', location, server.id);
                        }
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};