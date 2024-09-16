const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Data CMK Encrypted',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensures that MySQL flexible servers data is encrypted using CMK.',
    more_info: 'MySQL flexible server allows you to encrypt data using customer-managed keys (CMK) instead of using platform-managed keys, which are enabled by default. Using CMK encryption offers enhanced security and compliance, allowing centralized management and control of encryption keys through Azure Key Vault. It adds an extra layer of protection against unauthorized access to sensitive data stored in the database.',
    recommended_action: 'Ensure that MySQL flexible server have CMK encryption enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-customer-managed-key',
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
    
                if (flexibleServer.dataEncryption && flexibleServer.dataEncryption.primaryKeyURI) {
                    helpers.addResult(results, 0, 'MySQL flexible server data is encrypted using CMK', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'MySQL flexible server data is not encrypted using CMK', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
