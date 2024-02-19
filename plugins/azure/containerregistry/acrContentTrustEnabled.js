var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'ACR Content Trust Enabled',
    category: 'Container Registry',
    domain: 'Containers',
    severity: 'Low',
    description: 'Ensure that content trust is enabled for Azure premium container registries.',
    more_info: 'Content trust allows you to sign the images you push to your registry. Consumers of your images (people or systems pulling images from your registry) can configure their clients to pull only signed images which enhances container image security by ensuring the integrity and authenticity of images and safeguards against unauthorized or tampered content.',
    recommended_action: 'Modify your container registry and enable content trust.',
    link: 'https://learn.microsoft.com/en-us/azure/container-registry/container-registry-content-trust#enable-registry-content-trust',
    apis: ['registries:list'],
    realtime_triggers: ['microsoftcontainerregistry:registries:write','microsoftcontainerregistry:registries:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.registries, function(location, rcb) {

            var registries = helpers.addSource(cache, source,
                ['registries', 'list', location]);

            if (!registries) return rcb();

            if (registries.err || !registries.data) {
                helpers.addResult(results, 3,
                    'Unable to query for container registries: ' + helpers.addError(registries), location);
                return rcb();
            }

            if (!registries.data.length) {
                helpers.addResult(results, 0, 'No existing container registries found', location);
                return rcb();
            }

            for (let registry of registries.data) {
                if (!registry.id) continue;

                if (registry.sku && registry.sku.tier && registry.sku.tier.toLowerCase() !='premium') {
                    helpers.addResult(results, 0, 'Content trust is feature of Premium tier container registry', location, registry.id);
                } else {

                    var trustPolicy = registry.policies && registry.policies.trustPolicy? registry.policies.trustPolicy : null;

                    if (trustPolicy && trustPolicy.status && trustPolicy.status.toLowerCase() == 'enabled'){
                        helpers.addResult(results, 0, 'Content trust is enabled for container registry', location, registry.id);
                    } else {
                        helpers.addResult(results, 2, 'Content trust is not enabled for container registry', location, registry.id);
                    } 
                }
            }
            

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};