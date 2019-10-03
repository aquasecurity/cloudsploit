const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Watcher Enabled',
    category: 'Network Security Groups',
    description: 'Ensure that Network Watcher is Enabled on all locations.',
    more_info: 'Network Watchers help you understand, diagnose, and gain insights into the Azure networks. Enabling Network Watchers on all locations ensures that no resources are being used in locations that are not authorized by the company.',
    recommended_action: '1. Enter the Network Watcher Service. 2. Click the ... next to the Subscription name and Select Enable Network Watcher In All Regions.',
    link: 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview',
    apis: ['networkWatchers:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.resourceGroups, function(location, rcb){
            const networkWatchers = helpers.addSource(cache, source,
                ['networkWatchers', 'listAll', location]);

            if (!networkWatchers) return rcb();

            if (networkWatchers.err || !networkWatchers.data) {
                helpers.addResult(results, 3,
                    'Unable to query Network Watcher: ' + helpers.addError(networkWatchers), location);
                return rcb();
            };

            if (!networkWatchers.data.length) {
                helpers.addResult(results, 1, 'Network Watcher is not enabled in the region', location);
            };

            networkWatchers.data.forEach((networkWatcher) => {
                if (networkWatcher.provisioningState &&
                    networkWatcher.provisioningState == "Succeeded") {
                    helpers.addResult(results, 0, 'Network Watcher is enabled', location, networkWatcher.id);
                } else {
                    helpers.addResult(results, 2, 'Network Watcher is not enabled in the region', location, networkWatcher.id);
                };
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
