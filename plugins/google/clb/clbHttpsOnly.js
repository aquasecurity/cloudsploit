var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CLB HTTPS Only',
    category: 'CLB',
    domain: 'Availability',
    description: 'Ensures that HTTP(S) CLBs are configured to only accept connections on HTTPS ports.',
    more_info: 'For maximum security, CLBs can be configured to only accept HTTPS connections. Standard HTTP connections will be blocked. This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Remove non-HTTPS listeners from the load balancer.',
    apis: ['urlMaps:list', 'targetHttpProxies:list'],
    compliance: {
        pci: 'PCI requires strong cryptographic and security protocols ' +
            'when transmitting user data over open, public networks, ' +
            'this includes only using TLS or SSL.',
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'load balancer HTTPS redirection should be used to ensure site visitors ' +
            'are always connecting over a secure channel.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.targetHttpProxies, function(region, rcb){
            let urlMaps = helpers.addSource(
                cache, source, ['urlMaps', 'list', region]);

            if (!urlMaps) return rcb();

            if (urlMaps.err || !urlMaps.data) {
                helpers.addResult(results, 3, 'Unable to query Load Balancer', region, null, null, urlMaps.err);
                return rcb();
            }

            if (!urlMaps.data.length) {
                helpers.addResult(results, 0, 'No Load Balancers found', region);
                return rcb();
            }
            
            let httpProxies = helpers.addSource(
                cache, source, ['targetHttpProxies', 'list', region]);

            if (!httpProxies || httpProxies.err || !httpProxies.data) {
                helpers.addResult(results, 3, 'Unable to query HTTP proxies', region, null, null, httpProxies.err);
                return rcb();
            }

            for (let urlMap of urlMaps.data) {
                if (!urlMap.selfLink) continue;

                let clbResource = urlMap.selfLink.split('/').slice(5).join('/');
                let found = httpProxies.data.find(proxy => proxy.urlMap && proxy.urlMap.includes(clbResource));

                if (found) {
                    helpers.addResult(results, 2, 'Load Balancer is not HTTPS-Only', region, clbResource);
                } else {
                    helpers.addResult(results, 0, 'Load Balancer is HTTPS-Only', region, clbResource);
                }
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};