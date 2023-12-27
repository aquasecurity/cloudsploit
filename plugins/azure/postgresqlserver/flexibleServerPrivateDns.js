const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Private DNS Zone Integrated',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensure that PostgreSQL flexible servers has Private DNS Zone integrated.',
    more_info: 'Integrate Private DNS Zones with PostgreSQL flexible servers to enhance DNS service reliability and security within your Azure virtual network, ensuring seamless DNS resolution and streamlined domain management.',
    recommended_action: 'Ensures Vnet and Private DNS Zone (private access) is integrated for PostgreSQL flexible server.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-networking-private',
    apis: ['servers:listPostgresFlexibleServer'],

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
                if (!postgresServer.id) continue;
                
                if (flexibleServer.network && flexibleServer.network.privateDnsZoneArmResourceId) {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server has Private DNS Zone integrated', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server does not have Private DNS Zone integrated', location, flexibleServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
