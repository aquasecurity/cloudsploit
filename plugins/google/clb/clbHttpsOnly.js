var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'CLB HTTPS Only',
    category: 'CLB',
    description: 'Ensures CLBs are configured to only accept connections on HTTPS ports',
    more_info: 'For maximum security, CLBs can be configured to only accept HTTPS connections. Standard HTTP connections will be blocked. This should only be done if the client application is configured to query HTTPS directly and not rely on a redirect from HTTP.',
    link: 'https://cloud.google.com/vpc/docs/vpc',
    recommended_action: 'Remove non-HTTPS listeners from the load balancer.',
    apis: ['targetHttpProxies:list'],
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
            let httpProxies = helpers.addSource(
                cache, source, ['targetHttpProxies', 'list', region]);

            if (!httpProxies) return rcb();

            if (httpProxies.err || !httpProxies.data) {
                helpers.addResult(results, 3, 'Unable to query firewall rules: ' + helpers.addError(httpProxies), region);
                return rcb();
            }

            if (!httpProxies.data.length) {
                helpers.addResult(results, 0, 'No firewall rules found', region);
                return rcb();
            }
            var non_https_listener = [];
            httpProxies.data.forEach(httpProxy => {
                if (httpProxy.urlMap) {
                    var urlMap = httpProxy.urlMap.split('/');
                    var lbName = urlMap[urlMap.length-1];
                    non_https_listener.push(lbName);
                }
            });
            
            if (non_https_listener.length) {
                msg = "The following Load Balancers are not HTTPS-only: ";
                helpers.addResult(
                    results, 2, msg + non_https_listener.join(', '), region, null);
            } else{
                helpers.addResult(results, 0, 'No listeners found', region, null);
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}