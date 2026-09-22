var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Certificate Validity Period',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Key Vault certificates have a validity period of 12 months or less.',
    more_info: 'Limiting certificate validity reduces the risk of misuse if a certificate is compromised and helps ensure timely renewal, improving overall security and reliability.',
    recommended_action: 'Modify the certificate issuance policy and set the validity period to 12 months or less.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/certificates/create-certificate-scenarios',
    apis: ['vaults:list', 'vaults:getCertificates', 'getCertificatePolicy:get'],
    settings: {
        certificate_validity_period_fail: {
            name: 'Certificate Validity Period Fail',
            description: 'Return a failing result if the certificate validity period, in months, is greater than this number',
            regex: '^[1-9][0-9]{0,2}$',
            default: '12'
        }
    },
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            certificate_validity_period_fail: parseInt(settings.certificate_validity_period_fail || this.settings.certificate_validity_period_fail.default)
        };

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3, 'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach((vault) => {
                var certificates = helpers.addSource(cache, source,
                    ['vaults', 'getCertificates', location, vault.id]);

                if (!certificates || certificates.err || !certificates.data) {
                    helpers.addResult(results, 3, 'Unable to query for Key Vault certificates: ' + helpers.addError(certificates), location, vault.id);
                } else if (!certificates.data.length) {
                    helpers.addResult(results, 0, 'No Key Vault Certificates found', location, vault.id);
                } else {
                    certificates.data.forEach((certificate) => {
                        var certificatePolicy = helpers.addSource(cache, source,
                            ['getCertificatePolicy', 'get', location, certificate.id]);

                        if (!certificatePolicy || certificatePolicy.err || !certificatePolicy.data) {
                            helpers.addResult(results, 3, 'Unable to query for Certificate Policy: ' + helpers.addError(certificatePolicy), location, certificate.id);
                            return;
                        }

                        var validityMonths = certificatePolicy.data.x509_props ? certificatePolicy.data.x509_props.validity_months : undefined;

                        if (validityMonths === undefined || validityMonths === null) {
                            helpers.addResult(results, 3, 'Unable to determine certificate validity period', location, certificate.id);
                        } else if (validityMonths <= config.certificate_validity_period_fail) {
                            helpers.addResult(results, 0,
                                `Certificate validity period is set to ${validityMonths} months`, location, certificate.id);
                        } else {
                            helpers.addResult(results, 2,
                                `Certificate validity period is set to ${validityMonths} months which is greater than ${config.certificate_validity_period_fail}`, location, certificate.id);
                        }
                    });
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
