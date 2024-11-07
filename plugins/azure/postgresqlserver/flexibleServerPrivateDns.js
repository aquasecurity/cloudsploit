const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Private DNS Zone Integrated',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that PostgreSQL flexible servers have private DNS zone integrated.',
    more_info: 'Integrating Private DNS Zones with PostgreSQL flexible servers enhances DNS service reliability and security within your Azure virtual network, ensuring seamless DNS resolution and streamlined domain management.',
    recommended_action: 'Ensure Vnet and private DNS zone (private access) is integrated for PostgreSQL flexible server.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-private#using-private-dns-zone',
    apis: ['servers:listPostgresFlexibleServer'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgresFlexibleServer', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL flexible servers found', location);
                return rcb();
            }

            for (let flexibleServer of servers.data) {
                if (!flexibleServer.id) continue;
                
                if (flexibleServer.network && flexibleServer.network.privateDnsZoneArmResourceId) {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server has private DNS zone integrated', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server does not have private DNS zone integrated', location, flexibleServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
