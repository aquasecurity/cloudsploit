const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Network Access Default Action',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures that Storage Account access is restricted to trusted networks',
    more_info: 'Storage Accounts should be configured to accept traffic only from trusted networks. By default, all networks are selected but can be changed when creating a new storage account or in the firewall settings.',
    recommended_action: 'Configure the firewall of each Storage Account to allow access only from known virtual networks.',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/storage-network-security',
    apis: ['storageAccounts:list'],
    compliance: {
        pci: 'PCI requires data access to be configured to use a firewall. Removing the ' +
            'default network access action enables a more granular level of access controls.',
        hipaa: 'HIPAA access controls require data access to be restricted to known sources. ' +
            'Preventing default storage account access behavior enables a more granular level ' +
            'of access controls.'
    },
    settings: {
        storage_account_encryption_allow_pattern: {
            name: 'Storage Accounts Encryption Allow Pattern',
            description: 'When set, whitelists storage accounts matching the given pattern. Useful for overriding storage accounts that require default encryption.',
            regex: '^.{1,255}$',
            default: '^aquaacct([a-f0-9]){16}$'
        }
    },
    remediation_min_version: '202201032300',
    remediation_description: 'Default network action will be set to deny all traffic for affected storage accounts',
    apis_remediate: ['storageAccounts:list'],
    actions: {remediate:['storageAccounts:update'], rollback:['storageAccounts:update']},
    permissions: {remediate: ['storageAccounts:update'], rollback: ['storageAccounts:update']},
    realtime_triggers: ['microsoftstorage:storageaccounts:write'],

    run: function(cache, settings, callback) {
        var config = {
            storage_account_encryption_allow_pattern: settings.storage_account_encryption_allow_pattern || this.settings.storage_account_encryption_allow_pattern.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.storageAccounts, function(location, rcb) {
            const storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount),
                    location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            var allowRegex = (config.storage_account_encryption_allow_pattern &&
                config.storage_account_encryption_allow_pattern.length) ? new RegExp(config.storage_account_encryption_allow_pattern) : false;

            for (var acct in storageAccount.data) {
                const account = storageAccount.data[acct];

                // Different versions of the Azure API return different response
                // formats for this property, hence the extra check.
                if (allowRegex && allowRegex.test(account.name)) {
                    helpers.addResult(results, 0,
                        'Storage account: ' + account.name + ' is whitelisted via custom setting.',
                        location, account.id, custom);
                } else {
                    if (account.networkRuleSet &&
                        account.networkRuleSet.defaultAction &&
                        account.networkRuleSet.defaultAction.toLowerCase() === 'deny') {
                        helpers.addResult(results, 0, 'Storage Account default network access rule set to deny', location, account.id);
                    } else if (account.networkAcls &&
                        account.networkAcls.defaultAction &&
                        account.networkAcls.defaultAction.toLowerCase() === 'deny') {
                        helpers.addResult(results, 0, 'Storage Account default network access rule set to deny', location, account.id);
                    } else {
                        helpers.addResult(results, 2, 'Storage Account default network access rule set to allow from all networks', location, account.id);
                    }
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'networkAccessDefaultAction';
        var baseUrl = 'https://management.azure.com/{resource}?api-version=2021-04-01';
        var method = 'PATCH';

        // for logging purposes
        var saNameArr = resource.split('/');
        var saName = saNameArr[saNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'networkAcls': {
                        'defaultAction': 'Deny'
                    }
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'DefaultNetworkAction': 'Allow',
                'StorageAccount': saName
            };

            helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) return callback(err);
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Deny'
                };

                callback(null, action);
            });
        } else {
            callback('No region found');
        }
    }
};
