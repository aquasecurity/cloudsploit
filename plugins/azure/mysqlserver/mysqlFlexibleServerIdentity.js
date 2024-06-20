const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Managed Identity',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that MySQL flexible servers have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify MySQL flexible server add managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-azure-ad',
    apis: ['servers:listMysqlFlexibleServer'],   
    realtime_triggers: ['microsoftdbformysql:flexibleservers:write','microsoftdbformysql:flexibleservers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysqlFlexibleServer', location]);

            if (!servers) return rcb();
                
            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL flexible servers found', location);
                return rcb();
            }

            for (var flexibleServer of servers.data) {
                if (!flexibleServer.id) return;

                if (flexibleServer.identity) {
                    helpers.addResult(results, 0, 'MySQL flexible server has managed identity enabled', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'MySQL flexible server does not have managed identity enabled', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};