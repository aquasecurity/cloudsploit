const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Managed Identity Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that Azure SQL servers have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Entra ID tokens.',
    recommended_action: 'Enable system or user-assigned managed identities for sql servers.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-user-assigned-managed-identity?view=azuresql',
    apis: ['servers:listSql'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete'],

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

            servers.data.forEach((server) => {
                if (server.identity && server.identity.type && (server.identity.type.toLowerCase() == 'userassigned' || server.identity.type.toLowerCase() == 'systemassigned')) {
                    helpers.addResult(results, 0, 'SQL Server has managed identity enabled', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'SQL Server does not have managed identity enabled', location, server.id);
                }
            });
          
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
