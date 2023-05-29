const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Domain Public Access',
    category: 'Event Grid',
    domain: 'Messaging services',
    description: 'Ensure that Azure Event Grid domains do not have public access enabled.',
    more_info: 'Enabling public access for Event Grid domains can expose sensitive information and increase the risk of unauthorized access.',
    recommended_action: 'Modify the affected domain and disable public network access.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/configure-firewall',
    apis: ['recoveryServiceVaults:getRecoveryServiceVault', 'recoveryServiceVaults:listBySubscriptionId'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.recoveryServiceVaults, (location, rcb) => {
            const domains = helpers.addSource(cache, source, 
                ['recoveryServiceVaults', 'listBySubscriptionId', location]);
            if (!domains) return rcb();

            if (domains.err || !domains.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Event Grid domains: ' + helpers.addError(domains), location);
                return rcb();
            }

            if (!domains.data.length) {
                helpers.addResult(results, 0, 'No Event Grid domains found', location);
                return rcb();
            }
            console.log(domains.data)
            for (let vault of domains.data) {
                if (!vault.id) continue;

                const serviceVault = helpers.addSource(cache, source, 
                ['recoveryServiceVaults', 'getRecoveryServiceVault', location, vault.id]);

                if (!serviceVault.data || serviceVault.err) {
                    helpers.addResult(results, 3,
                    'Unable to query for Recovery Service Vault: ' + helpers.addError(domains), location);
                    continue;
                }
                console.log(serviceVault.data)
                // if (serviceVault.encryption && serviceVault.encryption.keyVaultProperties && serviceVault.encryption.keyVaultProperties.keyUri) {

                // }

            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};