const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'LB No Instances',
    category: 'Load Balancer',
    description: 'Detects load balancers that have no backend instances attached',
    more_info: 'All load balancers should have backend server resources. Those without any are consuming costs without providing any functionality. Additionally, old load balancers with no instances pose a security concern if new instances are accidentally attached.',
    link: 'https://docs.microsoft.com/en-us/azure/load-balancer/load-balancer-overview',
    recommended_action: 'Delete old load balancers that no longer have backend resources.',
    apis: ['loadBalancers:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.loadBalancers, function(location, rcb) {

            const loadBalancers = helpers.addSource(cache, source,
                ['loadBalancers', 'listAll', location]);

            if (!loadBalancers) return rcb();

            if (loadBalancers.err || !loadBalancers.data) {
                helpers.addResult(results, 3,
                    'Unable to query Load Balancers: ' + helpers.addError(loadBalancers), location);
                return rcb();
            }

            if (!loadBalancers.data.length) {
                helpers.addResult(results, 0, 'No existing Load Balancers', location);
                return rcb();
            }

            loadBalancers.data.forEach(loadBalancer => {
                var backendAmt = 0;
                
                if (!loadBalancer.backendAddressPools ||
                    (loadBalancer.backendAddressPools &&
                    !loadBalancer.backendAddressPools.length)) {
                    helpers.addResult(results, 2, 
                        'Load Balancer does not have any backend instances', location, loadBalancer.id);
                } else {
                    loadBalancer.backendAddressPools.forEach(backendAddressPool => {
                        if (backendAddressPool.properties &&
                            backendAddressPool.properties.backendIPConfigurations) {
                            backendAmt += backendAddressPool.properties.backendIPConfigurations.length;
                        } else if (backendAddressPool.properties &&
                            backendAddressPool.properties.loadBalancerBackendAddresses) {
                            backendAmt += backendAddressPool.properties.loadBalancerBackendAddresses.length;
                        }
                    });

                    if (backendAmt) {
                        helpers.addResult(results, 0, 
                            'Load Balancer has ' + backendAmt + ' backend ' + (backendAmt > 1 ? 'instances or addresses' : 'instance or address'), location, loadBalancer.id);
                    } else {
                        helpers.addResult(results, 2, 
                            'Load Balancer does not have any backend instances or addresses', location, loadBalancer.id);
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
