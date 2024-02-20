const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR CMK Encryption',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'High',
    description: 'Ensure that Microsoft Azure Container registries have CMK encryption enabled.',
    more_info: 'A customer-managed key gives you the ownership to bring your own key in Azure Key Vault. When you enable a customer-managed key, you can manage its rotations, control the access and permissions to use it, and audit its use.',
    recommended_action: 'Create new container registry with Premium SKU and enable CMK encryption.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/tutorial-customer-managed-keys',
    apis: ['registries:list'],
    realtime_triggers: ['microsoftcontainerregistry:registries:write','microsoftcontainerregistry:registries:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.registries, (location, rcb) => {
            var containerRegistries = helpers.addSource(cache, source, 
                ['registries', 'list', location]);

            if (!containerRegistries) return rcb();

            if (containerRegistries.err || !containerRegistries.data) {
                helpers.addResult(results, 3, 'Unable to query for Container registries: ' + helpers.addError(containerRegistries), location);
                return rcb();
            }

            if (!containerRegistries.data.length) {
                helpers.addResult(results, 0, 'No existing Container registries found', location);
                return rcb();
            } 
            
            for (let registry of containerRegistries.data) {
                if (!registry.id) continue;

                if (registry.encryption && registry.encryption.status && registry.encryption.status.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 0, 'Container Registry has CMK encryption enabled', location, registry.id);
                } else {
                    helpers.addResult(results, 2, 'Container Registry does not have CMK encryption enabled', location, registry.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
