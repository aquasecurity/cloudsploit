const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway SSL Policy',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    description: 'Ensures that Application Gateway is using minimum TLS version of TLSv1_2.',
    more_info: 'Transport Layer Security (TLS), previously known as Secure Sockets Layer (SSL), is the standard security technology for establishing an encrypted link between a web server and a browser. This link ensures that all data passed between the web server and browsers remain private and encrypted.',
    recommended_action: 'Modify Application Gateway with latest SSL policy which supports minimum TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-ssl-policy-overview',
    apis: ['applicationGateway:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        const recommendedSSLPolicies = ['AppGwSslPolicy20170401S', 'AppGwSslPolicy20220101' , 'AppGwSslPolicy20220101S'];
        
        async.each(locations.applicationGateway, (location, rcb) => {
            var appGateways = helpers.addSource(cache, source, 
                ['applicationGateway', 'listAll', location]);

            if (!appGateways) return rcb();

            if (appGateways.err || !appGateways.data) {
                helpers.addResult(results, 3, 'Unable to query for Application Gateway: ' + helpers.addError(appGateways), location);
                return rcb();
            }

            if (!appGateways.data.length) {
                helpers.addResult(results, 0, 'No existing Application Gateway found', location);
                return rcb();
            } 
            
            for (let appGateway of appGateways.data) {
                if (!appGateway.id) continue;

                const sslPolicy = appGateway.sslPolicy? appGateway.sslPolicy : '';
                if ((sslPolicy.policyType == 'Predefined' && sslPolicy.policyName && recommendedSSLPolicies.indexOf(sslPolicy.policyName) > -1) ||
                    (sslPolicy.policyType == 'Custom' && sslPolicy.minProtocolVersion && sslPolicy.minProtocolVersion.toLowerCase() == 'tlsv1_2')) {
                    helpers.addResult(results, 0, 'Application Gateway is using SSL policy which supports TLSV1_2', location, appGateway.id);
                } else {
                    helpers.addResult(results, 2, 'Application Gateway is using SSL policy which does not support TLSV1_2', location, appGateway.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
