const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Resources Usage Limits',
    category: 'Resources',
    description: 'Determines if resources are close to the Azure per-account limit',
    more_info: 'Azure limits accounts to certain numbers of resources. Exceeding those limits could prevent resources from launching.',
    recommended_action: 'Check if resources are close to the account limit to avoid resource launch failures',
    link: 'https://docs.microsoft.com/en-us/azure/azure-subscription-service-limits',
    apis: ['subscriptions:listLocations', 'usages:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.usages, function(location, rcb) {
            const subLocations = helpers.addSource(cache, source,
                ['subscriptions', 'listLocations', location]);

            if (!subLocations) return rcb();

            if (subLocations.err || !subLocations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for resource subscription locations: ' + helpers.addError(subLocations), location);
                return rcb();
            }

            if (!subLocations.data.length) {
                helpers.addResult(results, 0, 'No resource subscription locations found', location);
                return rcb();
            }

            subLocations.data.forEach(function(sloc){
                const usages = helpers.addSource(cache, source,
                    ['usages', 'list', location, sloc.id]);

                if (!usages || usages.err || !usages.data) {
                    if (usages && usages.err &&
                        usages.err.indexOf('No registered resource provider found for location') > -1) {
                        helpers.addResult(results, 0,
                            'Usage tracking is not supported by this location', location, sloc.id);
                    } else {
                        helpers.addResult(results, 3,
                            'Unable to query for Resource Usages: ' + helpers.addError(usages), location, sloc.id);
                    }
                } else if (!usages.data.length) {
                    helpers.addResult(results, 0, 'No Resource Usages', location, sloc.id);
                } else {
                    var limit100 = [];
                    var limit90 = [];
                    var limit70 = [];

                    usages.data.forEach(resource => {
                        if (resource.name &&
                            resource.limit &&
                            resource.currentValue &&
                            resource.name.localizedValue &&
                            ['Network Watchers'].indexOf(resource.name.localizedValue) === -1) {
                            var resourceName = resource.name.localizedValue;
                            var percentUsed = parseInt((resource.currentValue / resource.limit) * 100);
                            if (percentUsed >= 100) {
                                limit100.push(resourceName);
                            } else if (percentUsed >= 90) {
                                limit90.push(resourceName);
                            } else if (percentUsed >= 70) {
                                limit70.push(resourceName);
                            }
                        }
                    });

                    if (limit100.length || limit90.length || limit70.length) {
                        var msgStr = (limit70.length ? (' 70%: ' + limit70.join(', ')) : '');
                        msgStr += (limit90.length ? (' 90%: ' + limit90.join(', ')) : '');
                        msgStr += (limit100.length ? (' 100%: ' + limit100.join(', ')) : '');
                        helpers.addResult(results, 2, 'The following usage quotas are exceeded:' + msgStr, location, sloc.id);
                    } else {
                        helpers.addResult(results, 0, 'None of the resource usage limits exceed 70%', location, sloc.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
