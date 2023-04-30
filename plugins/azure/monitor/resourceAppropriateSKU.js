const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Monitor Azure Resource SKU',
    category: 'Monitor',
    domain: 'Management and Governance',
    description: 'Ensures that Basic or Consumption SKUs are not used on artifacts that need to be monitored.',
    more_info: 'Azure Monitor provides monitoring capabilities for resources and applications in Azure. Basic and Consumption SKUs provide limited monitoring capabilities compared to higher SKUs.',
    link: 'https://learn.microsoft.com/en-us/azure/search/search-sku-tier',
    recommended_action: 'Use a higher SKU for the resource to enable full monitoring capabilities.',
    apis: ['resources:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.resources, function(location, rcb) {

            const resources = helpers.addSource(cache, source, 
                ['resources', 'list', location]);

            if (!resources) return rcb();

            if (resources.err || !resources.data) {
                helpers.addResult(results, 3, 
                    'Unable to query for resources: ' + helpers.addError(resources), location);
                return rcb();
            }

            if (!resources.data.length){
                helpers.addResult(results, 0, 'No existing resource found', location);
            }

            for (let resource of resources.data) {
                if (!resource.id || !resource.sku) continue;
                
                if (resource.sku && (resource.sku.name.toLowerCase() === 'basic' ||resource.sku.name.toLowerCase() === 'consumption')){
                    helpers.addResult(results, 2, `Azure Resource is using ${resource.sku.name} SKU`, location, resource.id);
                } else {
                    helpers.addResult(results, 0, `Azure Resource is using ${resource.sku.name} SKU`, location, resource.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};