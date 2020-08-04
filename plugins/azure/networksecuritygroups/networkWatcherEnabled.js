const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Network Watcher Enabled',
    category: 'Network Security Groups',
    description: 'Ensures Network Watcher is enabled in all locations',
    more_info: 'Network Watcher helps locate, diagnose, and gain insights into Azure networks. Enabling Network Watcher in all locations ensures that no resources are being used in locations that are not authorized.',
    recommended_action: 'Enable the Network Watcher service in all locations.',
    link: 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview',
    apis: ['networkWatchers:listAll', 'virtualNetworks:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkWatchers, function(location, rcb){
            const networkWatchers = helpers.addSource(cache, source,
                ['networkWatchers', 'listAll', location]);

            const virtualNetworks = helpers.addSource(cache, source,
                ['virtualNetworks', 'listAll', location]);

            if (!networkWatchers || !virtualNetworks) return rcb();

            if (networkWatchers.err || !networkWatchers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Network Watchers: ' + helpers.addError(networkWatchers), location);
                return rcb();
            }

            if (virtualNetworks.err || !virtualNetworks.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Virtual Networks: ' + helpers.addError(virtualNetworks), location);
                return rcb();
            }

            if (!networkWatchers.data.length && virtualNetworks.data.length) {
                helpers.addResult(results, 2, 'Network Watcher is not enabled in the region', location);
            } else if (!networkWatchers.data.length && !virtualNetworks.data.length) {
                helpers.addResult(results, 0, 'No Virtual Networks or Network Watchers in the region', location);
            }

            networkWatchers.data.forEach((networkWatcher) => {
                if (networkWatcher.provisioningState &&
                    networkWatcher.provisioningState.toLowerCase() == 'succeeded') {
                    helpers.addResult(results, 0, 'Network Watcher is enabled', location, networkWatcher.id);
                } else {
                    helpers.addResult(results, 2, 'Network Watcher is not successfully provisioned for the region', location, networkWatcher.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
