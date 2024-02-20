var async = require('async');
var helpers = require('../../../helpers/azure');
var _ = require('underscore');

module.exports = {
    title: 'Manage Key Access and Permissions',
    category: 'Key Vaults',
    domain: 'Application Integration',
    severity: 'Low',
    description: 'Ensures that no Microsoft Azure user, group or application has administrator privileges to the Key Vaults.',
    more_info: 'A principal such as a user, group or application should have access to execute only specific operations for Azure Key Vault keys, secrets or certificates as a security best practice.',
    recommended_action: 'Ensure that no Microsoft Azure user, group or application is using administrator privileges.',
    link: 'https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide?tabs=azure-cli',
    apis: ['vaults:list'],
    realtime_triggers: ['microsoftkeyvault:vaults:write', 'microsoftkeyvault:vaults:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

            const fullPermissions = {
                'certificates': [
                    'Get',
                    'List',
                    'Update',
                    'Create',
                    'Import',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'ManageContacts',
                    'ManageIssuers',
                    'GetIssuers',
                    'ListIssuers',
                    'SetIssuers',
                    'DeleteIssuers',
                    'Purge'
                ],
                'keys': [
                    'Get',
                    'List',
                    'Update',
                    'Create',
                    'Import',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'Decrypt',
                    'Encrypt',
                    'UnwrapKey',
                    'WrapKey',
                    'Verify',
                    'Sign',
                    'Purge'
                ],
                'secrets': [
                    'Get',
                    'List',
                    'Set',
                    'Delete',
                    'Recover',
                    'Backup',
                    'Restore',
                    'Purge'
                ],
                'storage': [
                    'get',
                    'list',
                    'delete',
                    'set',
                    'update',
                    'regeneratekey',
                    'setsas',
                    'listsas',
                    'getsas',
                    'deletesas'
                ]
            };

            vaults.data.forEach((vault) => {
                let policyFound = false;

                vault.accessPolicies.forEach((policy) => {
                    if (_.isEqual(fullPermissions, policy.permissions)) {
                        policyFound = true;
                    }
                });

                if (policyFound) {
                    helpers.addResult(results, 2,
                        'User/Group or Application has full access to the vault', location, vault.id);
                } else {
                    helpers.addResult(results, 0,
                        'No User/Group or Application has full access to the vault', location, vault.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
