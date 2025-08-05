var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Key Vault Public Access',
    category: 'Key Vault',
    domain: 'Security',
    severity: 'High',
    description: 'Ensures that Azure Key Vaults do not allow unrestricted public access',
    more_info: 'Azure Key Vaults should be configured to restrict public access to protect sensitive data. This can be achieved by either disabling public network access or implementing strict network rules.',
    recommended_action: 'Modify Key Vault network settings to disable public access or appropriate configure network rules.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/network-security',
    apis: ['vaults:list'],
    settings: {
        keyvault_allowed_ips: {
            name: 'Key Vault Allowed IPs',
            description: 'Comma-separated list of IP addresses that are explicitly allowed to access Key Vaults',
            regex: '^(?:\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}(?:/\\d{1,2})?(?:,\\s*)?)+$',
            default: ''
        }
    },
    realtime_triggers: ['microsoft.keyvault:vaults:write', 'microsoft.keyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            keyvault_allowed_ips: settings.keyvault_allowed_ips || this.settings.keyvault_allowed_ips.default
        };

        var allowedIps = [];
        if (config.keyvault_allowed_ips && config.keyvault_allowed_ips.length) {
            allowedIps = config.keyvault_allowed_ips.split(',').map(ip => ip.trim());
        }
        var checkAllowedIps = allowedIps.length > 0;

        async.each(locations.vaults, function(location, rcb) {
            var vaults = helpers.addSource(cache, source,
                ['vaults', 'list', location]);

            if (!vaults) return rcb();

            if (vaults.err || !vaults.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Key Vaults: ' + helpers.addError(vaults), location);
                return rcb();
            }

            if (!vaults.data.length) {
                helpers.addResult(results, 0, 'No Key Vaults found', location);
                return rcb();
            }

            vaults.data.forEach(function(vault) {
                if (!vault.id) return;

                if (vault && 
                    vault.publicNetworkAccess && 
                    vault.publicNetworkAccess.toLowerCase() === 'disabled') {
                    helpers.addResult(results, 0,
                        'Key Vault is protected from outside traffic',
                        location, vault.id);
                    return;
                }

             
                if (vault && vault.networkAcls) {
                    var networkAcls = vault.networkAcls;
                    var defaultAction = networkAcls.defaultAction ? networkAcls.defaultAction.toLowerCase() : null;
                    
                    if (!defaultAction || defaultAction === 'allow') {
                        helpers.addResult(results, 2,
                            'Key Vault is open to outside traffic',
                            location, vault.id);
                        return;
                    }

                    if (defaultAction === 'deny') {
                        var ipRules = networkAcls.ipRules || [];
                        var hasPublicAccess = false;
                        var publicAccessFound = [];

                        for (var rule of ipRules) {
                            if (checkAllowedIps) {
                                if ((rule.value === '0.0.0.0/0' || rule.value === '0.0.0.0') &&
                                    !allowedIps.includes(rule.value)) {
                                    hasPublicAccess = true;
                                    publicAccessFound.push(rule.value);
                                }
                            } else if (rule.value === '0.0.0.0/0' || rule.value === '0.0.0.0') {
                                hasPublicAccess = true;
                                publicAccessFound.push(rule.value);
                            }
                        }

                        if (hasPublicAccess) {
                            helpers.addResult(results, 2,
                                `Key Vault is open to outside traffic through IP rules: ${publicAccessFound.join(', ')}`,
                                location, vault.id);
                        } else {
                            var message = 'Key Vault is protected from outside traffic';
                            helpers.addResult(results, 0, message, location, vault.id);
                        }
                    }
                } else {
                    helpers.addResult(results, 2,
                        'Key Vault is open to outside traffic',
                        location, vault.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
}; 