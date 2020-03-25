var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Azure Active Directory Admin Enabled',
    category: 'SQL Server',
    description: 'Ensures that Active Directory admin is enabled on all SQL servers.',
    more_info: 'Enabling Active Directory admin allows users to manage account admins in a central location, allowing key rotation and permission management to be managed in one location for all servers and databases.',
    recommended_action: 'Ensure Azure Active Directory admin is enabled on all SQL servers.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-aad-authentication-configure',
    apis: ['resourceGroups:list', 'servers:sql:list', 'serverAzureADAdministrators:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.serverAzureADAdministrators, function (location, rcb) {
            const servers = helpers.addSource(cache, source,
                ['servers', 'sql', 'list', location]);

            const serverAzureADAdministrators = helpers.addSource(cache, source,
                ['serverAzureADAdministrators', 'listByServer', location]);

            if (!servers) return rcb();

            if (!serverAzureADAdministrators) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for sql servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (serverAzureADAdministrators.err || !serverAzureADAdministrators.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Active Directory Admins: ' + helpers.addError(serverAzureADAdministrators), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No sql servers found', location);
                return rcb();
            }

            var allServers = servers.data.map(server => {
                return server.id;
            });

            serverAzureADAdministrators.data.forEach(serverAzureADAdministrator => {
                var serverIdArr = serverAzureADAdministrator.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');
                if (serverAzureADAdministrator.name &&
                    serverAzureADAdministrator.name === 'ActiveDirectory') {
                    if (allServers.indexOf(serverId) > -1) {
                        allServers.splice(allServers.indexOf(serverId), 1);
                    }
                    helpers.addResult(results, 0,
                        'Active directory admin is enabled on the sql server', location, serverId);
                }
            });

            if (allServers.length) {
                var allServersStr = allServers.join(', ');
                helpers.addResult(results, 2,
                    `Active directory admin is not enabled on the following sql servers: ${allServersStr}`, location);
            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};