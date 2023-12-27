const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server VNet integrated',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensure that PostgreSQL flexible servers has VNet integrated.',
    more_info: 'Configuring PostgreSQL flexible server to operate within a Virtual Network (VNet) offers a myriad of benefits for enhanced security and operational control. By integrating with a VNet, you are proactively safeguarding your server against potential security threats and unauthorized access.',
    recommended_action: 'Ensures Vnet (private access) is integrated for PostgreSQL flexible server.',
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
                if (flexibleServer.network && flexibleServer.network.delegatedSubnetResourceId) {
                    helpers.addResult(results, 0, 'PostgreSQL flexible server has VNet integrated', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL flexible server does not have VNet integrated', location, flexibleServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
