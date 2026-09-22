const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway HTTP2 Enabled',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    severity: 'Low',
    description: 'Ensures that HTTP2 is enabled for Application Gateways.',
    more_info: 'HTTP2 support is available to clients that connect to application gateway listeners and provides improved performance and efficiency over HTTP1.1. Clients and backend services that do not support HTTP2 fall back to HTTP1.1.',
    recommended_action: 'Enable HTTP2 from the configuration settings of the application gateway.',
    link: 'https://learn.microsoft.com/en-us/azure/application-gateway/configuration-overview',
    apis: ['applicationGateway:listAll'],
    realtime_triggers: ['microsoftnetwork:applicationgateways:write', 'microsoftnetwork:applicationgateways:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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

                if (appGateway.enableHttp2) {
                    helpers.addResult(results, 0, 'HTTP2 is enabled for Application Gateway', location, appGateway.id);
                } else {
                    helpers.addResult(results, 2, 'HTTP2 is not enabled for Application Gateway', location, appGateway.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
