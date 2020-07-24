const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'LB HTTPS Only',
    category: 'Load Balancer',
    description: 'Ensures load balancers are configured to only accept connections on HTTPS ports',
    more_info: 'For maximum security, load balancers can be configured to only accept HTTPS connections. Standard HTTP connections will be blocked. This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.',
    link: 'https://docs.microsoft.com/en-us/azure/load-balancer/load-balancer-overview',
    recommended_action: 'Ensure that each load balancer only accepts connections on port 443.',
    apis: ['loadBalancers:listAll'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
                'App Service HTTPS redirection should be used to ensure site visitors ' +
                'are always connecting over a secure channel.',
    },

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
                helpers.addResult(results, 0, 'No existing Load Balancers found', location);
                return rcb();
            }

            loadBalancers.data.forEach(loadBalancer => {
                var notHTTPSRules = 0;
                var isHTTPS = false;

                if (loadBalancer.inboundNatRules &&
                    loadBalancer.inboundNatRules.length > 0) {
                    loadBalancer.inboundNatRules.forEach(inboundRule => {
                        if (inboundRule.properties &&
                            inboundRule.properties.frontendPort &&
                            inboundRule.properties.frontendPort == 443) {
                            isHTTPS = true;
                        } else {
                            notHTTPSRules++;
                        }
                    });
                }

                if (loadBalancer.loadBalancingRules &&
                    loadBalancer.loadBalancingRules.length > 0) {
                    loadBalancer.loadBalancingRules.forEach(loadBalancingRule => {
                        if (loadBalancingRule.properties &&
                            loadBalancingRule.properties.frontendPort &&
                            loadBalancingRule.properties.frontendPort == 443) {
                            isHTTPS = true;
                        } else {
                            notHTTPSRules++;
                        }
                    });
                }

                if (notHTTPSRules && isHTTPS) {
                    helpers.addResult(results, 2,
                        'HTTPS is configured but other ports are open', location, loadBalancer.id);
                } else if (notHTTPSRules && !isHTTPS) {
                    helpers.addResult(results, 2,
                        'HTTPS is not configured and other ports are open', location, loadBalancer.id);
                } else if (isHTTPS) {
                    helpers.addResult(results, 0,
                        'Only HTTPS is configured', location, loadBalancer.id);
                } else {
                    helpers.addResult(results, 0,
                        'No inbound rules found', location, loadBalancer.id);
                }
            });
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
