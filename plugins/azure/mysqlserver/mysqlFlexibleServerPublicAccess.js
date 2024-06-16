const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Public Access Disabled',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that MySQL Flexible servers are not publicly accessible.',
    more_info: 'Configuring public access on for MySQL flexible server instance allows the server to be accessible through a public endpoint. This can expose the server to unauthorized access and various cyber threats. Disabling public access enhances security by limiting access to authorized connections only.',
    recommended_action: 'Modify MySQL flexible server and disable public network access.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-networking-public',
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
                if (!flexibleServer.id) continue;
    
                if (flexibleServer.properties &&
                    flexibleServer.properties.network && 
                    flexibleServer.properties.network.publicNetworkAccess &&
                    flexibleServer.properties.network.publicNetworkAccess.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 2, 'MySQL flexible server is publicly accessible', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 0, 'MySQL flexible server is not publicly accessible', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
