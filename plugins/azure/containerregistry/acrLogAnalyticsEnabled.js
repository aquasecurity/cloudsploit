const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'ACR Log Analytics Enabled',
    category: 'Container Registry',
    domain: 'Containers',
    description: 'Ensure that Azure Container registry logs are sent to the Log Analytics workspace.',
    more_info: 'Enabling Log Analytics for Azure Container registry ensures that logs are shipped to a central repository that can be queried and audited.',
    recommended_action: 'Modify container registry and enable Send to Log Analytics from diagnostic settings.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/monitor-service',
    apis: ['registries:list', 'diagnosticSettings:listByContainerRegistries'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.registries, (location, rcb) => {
            const registries = helpers.addSource(cache, source,
                ['registries', 'list', location]);

            if (!registries) return rcb();

            if (registries.err || !registries.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Container Registries: ' + helpers.addError(registries), location);
                return rcb();
            }

            if (!registries.data.length) {
                helpers.addResult(results, 0, 'No existing Container Registries found', location);
                return rcb();
            }

            for (let registry of registries.data) {
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByContainerRegistries', location, registry.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query diagnostics settings: ' + helpers.addError(diagnosticSettings), location, registry.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing diagnostics settings', location, registry.id);
                } else {  
                    var found = false;
                    diagnosticSettings.data.forEach(function(ds) {
                        if (ds.logs && ds.logs.length) found = true;
                    });

                    if (found) {
                        helpers.addResult(results, 0, 'Log Analytics enabled for ACR', location, registry.id);
                    } else {
                        helpers.addResult(results, 2, 'Log Analytics are not enabled for ACR', location, registry.id);
                    }
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
