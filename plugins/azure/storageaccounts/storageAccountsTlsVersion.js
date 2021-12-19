var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Minimum TLS Version',
    category: 'SQL Server',
    domain: 'Databases',
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
            default: '1.1'
        }
    },

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
    }
};