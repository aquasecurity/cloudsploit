var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Service Certificates Expiry',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Detect upcoming expiration of App Service Certificates.',
    more_info: 'Azure App Service Certificates help in securing DNS Domain for the web app of function app. Certificates auto-renewal should be configured to avoid any un expected results.',
    recommended_action: 'Turn On Certificates auto -renewal for Azure App Service Certificates',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/configure-ssl-certificate',
    apis: ['appServiceCertificates:list'],
    settings: {
        days_to_expire: {
            name: 'Days Before Expiration of Certificate',
            description: 'Threshold to reach certificate expiry date (days)',
            regex: '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-9][0-9]|3[0-5][0-9]|36[0-5])$',
            default: '60',
        }
    },
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        const config = {
            daysToExpire: parseInt(settings.days_to_expire || this.settings.days_to_expire.default)
        };

        async.each(locations.appServiceCertificates, function(location, rcb) {
            const appServiceCertificates = helpers.addSource(cache, source,
                ['appServiceCertificates', 'list', location]);

            if (!appServiceCertificates) return rcb();

            if (appServiceCertificates.err || !appServiceCertificates.data) {
                helpers.addResult(results, 3, 'Unable to query for App Service Certificates : ' + helpers.addError(appServiceCertificates), location);
                return rcb();
            }

            if (!appServiceCertificates.data.length) {
                helpers.addResult(results, 0, 'No existing App Service Certificates found', location);
                return rcb();
            }

            async.each(appServiceCertificates.data, function(certificate, scb) {
                if (certificate.expirationDate) {
                    const daysToExpire = Math.round((new Date(certificate.expirationDate).getTime() - new Date().getTime()) / (24 * 60 * 60 * 1000));

                    if (daysToExpire > config.daysToExpire) {
                        helpers.addResult(results, 0, `App Service Certificate expires in ${Math.abs(daysToExpire)} days`, location, certificate.id);
                    } else if (daysToExpire >= 0) {
                        helpers.addResult(results, 2, `App Service Certificate expires in ${Math.abs(daysToExpire)} days`, location, certificate.id);
                    } else {
                        helpers.addResult(results, 2, `App Service Certificate expired ${Math.abs(daysToExpire)} days ago`, location, certificate.id);
                    }
                } else {
                    helpers.addResult(results, 3, 'App Service Certificate does not have an expiration date configured', location, certificate.id);
                }
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
