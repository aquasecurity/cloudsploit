var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Allowed Certificates Key Types',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that Microsoft Azure Key Vault SSL certificates are using the allowed key types.',
    more_info: 'Having the right key type set for your Azure Key Vault SSL certificates will enforce the best practices as specified in the security and compliance regulations implemented within your organization.',
    recommended_action: 'Ensure that Key Vault SSL certificates are using the allowed key types.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/certificates/certificate-access-control',
    apis: ['vaults:list', 'vaults:getCertificates', 'getCertificatePolicy:get'],
    settings: {
        allowed_certificate_key_types: {
            name: 'Key Vault Certificate Key Types',
            description: 'Comma separated key types supported for certificates in Azure Key Vault',
            regex: '^(RSA|EC)$',
            default: ''
        }
    },
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            allowed_certificate_key_types: settings.allowed_certificate_key_types || this.settings.allowed_certificate_key_types.default,
        };

        if (!config.allowed_certificate_key_types.length) return callback(null, results, source);

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
                        } else {
                            const certificateKeys = certificatePolicy.data.key_props;
                            if (certificateKeys && certificateKeys.kty) {
                                if (config.allowed_certificate_key_types.toLowerCase().includes(certificateKeys.kty.toLowerCase())) {
                                    helpers.addResult(results, 0, 'Certificate key type is ' + certificateKeys.kty, location, certificate.id);
                                } else {
                                    helpers.addResult(results, 2, 'Certificate key type is ' + certificateKeys.kty, location, certificate.id);
                                }
                            } else {
                                helpers.addResult(results, 3, 'Unable to list key type for Key Vault Certificate: ' + helpers.addError(certificatePolicy), location, certificate.id);
                            }
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
