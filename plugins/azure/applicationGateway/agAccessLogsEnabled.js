const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Application Gateway Access Logs Enabled',
    category: 'Application Gateway',
    domain: 'Network Access Control',
    description: 'Ensures that Application Gateway Access Log is enabled.',
    more_info: 'Application Gateway logs provide detailed information for events related to a resource and its operations. Access logs helps to analyze important information includeing the caller\'s IP, requested URL, response latency, return code, and bytes in and out. An access log is collected every 60 seconds.',
    recommended_action: 'Ensure that diagnostic setting for Application Gateway Access Log is enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/application-gateway/application-gateway-diagnostics',
    apis: ['applicationGateway:listAll', 'diagnosticSettings:listByApplicationGateways'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        async.each(locations.applicationGateway, (location, rcb) => {
            const applicationGateways = helpers.addSource(cache, source,
                ['applicationGateway', 'listAll', location]);

            if (!applicationGateways) return rcb();

            if (applicationGateways.err || !applicationGateways.data) {
                helpers.addResult(results, 3,
                    'Unable to query Application Gateway: ' + helpers.addError(applicationGateways), location);
                return rcb();
            }

            if (!applicationGateways.data.length) {
                helpers.addResult(results, 0, 'No existing Application Gateway found', location);
                return rcb();
            }

            applicationGateways.data.forEach(function(appGateway) {
                if (!appGateway.id) return;
                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByApplicationGateways', location, appGateway.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, 'Unable to query Application Gateway diagnostics settings: ' + helpers.addError(diagnosticSettings), location, appGateway.id);
                } else if (!diagnosticSettings.data.length) {
                    helpers.addResult(results, 2, 'No existing Application Gateway diagnostics settings found', location, appGateway.id);
                } else {
                    var accessLogsEnabled = helpers.diagnosticSettingLogs(diagnosticSettings, 'ApplicationGatewayAccessLog', ['allLogs']);
                    if (accessLogsEnabled) {
                        helpers.addResult(results, 0, 'Application Gateway access logs are enabled', location, appGateway.id);
                    } else {
                        helpers.addResult(results, 2, 'Application Gateway access logs are not enabled', location, appGateway.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};