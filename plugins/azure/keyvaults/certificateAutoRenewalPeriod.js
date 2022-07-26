var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SSL Certificate Auto Renewal Period',
    category: 'Key Vaults',
    domain: 'Application Integration',
    description: 'Ensures that Microsoft Azure Key Vault SSL certificates have auto-renewal period configured for security and compliance purposes.',
    more_info: 'Setting the right number of days before expiration set to trigger auto-renewal for your Azure Key Vault SSL certificates, will enforce your certificate renewal strategy to follow the best practices as specified in the compliance regulations implemented within your organization.',
    recommended_action: 'Ensure that Key Vault SSL certificates are configured to have auto renewal period.',
    link: 'https://docs.microsoft.com/en-us/azure/key-vault/certificates/certificate-scenarios',
    apis: ['vaults:list', 'vaults:getCertificates', 'getCertificatePolicy:get'],
    settings: {
        key_vault_certificate_expiry_days: {
            name: 'Key Vault Certificate Expiry Days',
            description: 'Return a failing result when certificate expiration date is within this number of days in the future for triggering auto renewal',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '30'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            key_vault_certificate_expiry_days: parseInt(settings.key_vault_certificate_expiry_days || this.settings.key_vault_certificate_expiry_days.default)
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
                            if (certificatePolicy.data.attributes && certificatePolicy.data.attributes.enabled) {
                                const lifetimeActions = certificatePolicy.data.lifetime_actions;
    
                                let autoRenewPeriod = lifetimeActions && lifetimeActions.find(lifetimeAction =>
                                    lifetimeAction.trigger && lifetimeAction.trigger.days_before_expiry &&
                                    lifetimeAction.trigger.days_before_expiry === 30);

                                if (autoRenewPeriod){
                                    if (autoRenewPeriod.trigger.days_before_expiry <= config.key_vault_certificate_expiry_days) {
                                        helpers.addResult(results, 0, `SSL Certificate has ${autoRenewPeriod.trigger.days_before_expiry} or more than ${autoRenewPeriod.trigger.days_before_expiry} days before triggering auto renewal process`, location, certificate.id);
                                    } else {
                                        helpers.addResult(results, 2, `SSL Certificate has less than ${autoRenewPeriod.trigger.days_before_expiry} days before triggering auto renewal process`, location, certificate.id);
                                    }
                                } else {
                                    helpers.addResult(results, 0, 'SSL Certificate auto renewal period is not enabled', location, certificate.id);
                                }
                            } else {
                                helpers.addResult(results, 0, 'SSL Certificate is not enabled', location, certificate.id);
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
