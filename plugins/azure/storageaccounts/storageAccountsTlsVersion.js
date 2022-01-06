var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Accounts Minimum TLS Version',
    category: 'Storage Accounts',
    domain: 'Storage',
    description: 'Ensures Microsoft Azure Storage Accounts are using the latest TLS version 1.2 to enforce stricter security measure.',
    more_info: 'Azure Storage accounts permit clients to send and receive data with the oldest version of TLS, TLS 1.0, and above. ' +
        'To enforce stricter security measures, you can configure your storage account to require that clients send and receive data with a newer version of TLS.',
    recommended_action: 'Modify Storage Account configuration and set desired minimum TLS version',
    link: 'https://docs.microsoft.com/en-us/azure/storage/common/transport-layer-security-configure-minimum-version',
    apis: ['storageAccounts:list'],
    settings: {
        sa_min_tls_version: {
            name: 'Storage Account Minimum TLS Version',
            description: 'Minimum desired TLS version for Microsoft Azure Storage Accounts',
            regex: '^(1.0|1.1|1.2)$',
            default: '1.2'
        }
    },
    remediation_min_version: '202112312200',
    remediation_description: 'TLS version 1.2 will be set for the affected Storage Accounts',
    apis_remediate: ['storageAccounts:list'],
    actions: {remediate:['storageAccounts:update'], rollback:['storageAccounts:update']},
    permissions: {remediate: ['storageAccounts:update'], rollback: ['storageAccounts:update']},
    realtime_triggers: ['microsoftstorage:storageaccounts:write'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        var config = {
            sa_min_tls_version: settings.sa_min_tls_version || this.settings.sa_min_tls_version.default
        };

        var desiredVersion = parseFloat(config.sa_min_tls_version);

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccounts = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccounts) return rcb();

            if (storageAccounts.err || !storageAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccounts), location);
                return rcb();
            }

            if (!storageAccounts.data.length) {
                helpers.addResult(results, 0, 'No Storage Accounts found', location);
                return rcb();
            }

            storageAccounts.data.forEach(function(storageAccount) {
                if (!storageAccount.id) return;

                let tlsVersion = storageAccount.minimumTlsVersion ? storageAccount.minimumTlsVersion : 'TLS1.0'; //Default is TLS 1.0
                tlsVersion = tlsVersion.replace('TLS', '');
                tlsVersion = tlsVersion.replace('_', '.');
 
                if (parseFloat(tlsVersion) >= desiredVersion) {
                    helpers.addResult(results, 0,
                        `Storage Account is using TLS version ${tlsVersion} which is equal to or higher than desired TLS version ${config.sa_min_tls_version}`,
                        location, storageAccount.id);
                } else {
                    helpers.addResult(results, 2,
                        `Storage Account is using TLS version ${tlsVersion} which is less than desired TLS version ${config.sa_min_tls_version}`,
                        location, storageAccount.id);   
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'storageAccountsTlsVersion';
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
                    'minimumTlsVersion': 'TLS1_2'
                }
            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'TLS1.2': 'Disabled',
                'StorageAccount': saName
            };

            helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) return callback(err);
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Enabled'
                };

                callback(null, action);
            });
        } else {
            callback('No region found');
        }
    }
};