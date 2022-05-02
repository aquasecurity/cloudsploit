var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'RSA Certificate Allowed Key Size',
    category: 'Key Vaults',
    domain: 'Identity and Access Management',
    description: 'Ensures that Microsoft Azure Key Vault RSA certificates are using the allowed key size.',
    more_info: 'Having the right key type size for your Azure Key Vault RSA certificates will enforce the best practices as specified in the security and compliance regulations implemented within your organization.',
    recommended_action: 'Ensure that Key Vault RSA certificates are using the allowed key types.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/certificates/about-certificates',
    apis: ['vaults:list', 'vaults:getCertificates', 'getCertificatePolicy:get'],
    settings: {
        rsa_certificate_key_size: {
            name: 'RSA Certificate Allowed Key Size',
            description: 'Key sizes supported for rsa certificates in Azure Key Vault',
            regex: '^(2048|3072|4096)$',
            default: '2048'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        var config = {
            rsa_certificate_key_size: settings.rsa_certificate_key_size || this.settings.rsa_certificate_key_size,
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
                        } else {
                            const certificateKeys = certificatePolicy.data.key_props;

                            if (certificateKeys && certificateKeys.kty) {
                                const allowedKeySize = new RegExp(config.rsa_certificate_key_size.regex);

                                if (allowedKeySize.test(certificateKeys.key_size)) {
                                    helpers.addResult(results, 0, 'RSA Certificate key size is within the Allowed Key Sizes: ' + certificateKeys.key_size, location, certificate.id);
                                } else {
                                    helpers.addResult(results, 2, 'RSA Certificate key size is not within the Allowed Key Sizes: ' + certificateKeys.key_size, location, certificate.id);
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
