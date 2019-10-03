const async = require('async');

const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Resources Max Instances',
    category: 'Resources',
    description: 'Determine if resources are close to the Azure per-account limit',
    more_info: 'Azure limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    recommended_action: 'Check if resources are rclose to limit to avoid resource launching',
    link: 'https://docs.microsoft.com/en-us/azure/azure-subscription-service-limits',
    apis: ['subscriptions:listLocations','usages:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.usages, function (location, rcb) {

            const usages = helpers.addSource(cache, source, 
                ['usages', 'list', location]);

            if (!usages) return rcb();

            if (usages.err || !usages.data) {
                helpers.addResult(results, 3,
                    'Unable to query Resource Usages: ' + helpers.addError(usages), location);
                return rcb();
            }

            if (!usages.data.length) {
                helpers.addResult(results, 3, 'No Usage Data Found', location)
                return rcb();
            }

            var region;
            var locFlag = false;
            usages.data.forEach(resource => {
                if (resource.name.value == 'NetworkWatchers') return;
                
                var resourceName = resource.name.localizedValue;
                var idArr = resource.id.split('/');

                var resourceLoc = idArr[idArr.length-3];
                if (locations.all.indexOf(resourceLoc) === -1) {
                    return
                }
                if (!region) {
                    region = resourceLoc;
                } else if (resourceLoc != region) {
                    if (!locFlag) {
                        helpers.addResult(results, 0, 'No Resources in the region are close to the max limit.', region);
                    };
                    region = resourceLoc;
                    locFlag = false;
                }

                let percentUsed = parseInt((resource.currentValue / resource.limit) * 100);
                if (percentUsed == 100) {
                    helpers.addResult(results, 2, `All ${resourceName} are used`, resourceLoc, resource.id);
                    locFlag = true;
                } else if (percentUsed >= 90) {
                    helpers.addResult(results, 1, `More than 90% of ${resourceName} are used`, resourceLoc, resource.id);
                    locFlag = true;
                } else if (percentUsed >= 70) {
                    helpers.addResult(results, 1, `More than 70% of ${resourceName} are used`, resourceLoc, resource.id);
                    locFlag = true;
                }
            });
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
