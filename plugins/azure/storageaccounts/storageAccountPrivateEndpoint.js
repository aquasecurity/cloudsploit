var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Storage Account Private Endpoints',
    category: 'Storage Accounts',
    domain: 'Storage',
    severity: 'Medium',
    description: 'Ensure that Azure Storage accounts are accessible only through private endpoints or have restricted public access.',
    more_info: 'Azure Private Endpoint is a network interface that connects you privately and securely to a service powered by Azure Private Link. Private Endpoint uses a private IP address from your VNet, effectively bringing the service such as Azure Storage Accounts into your VNet. If private endpoints are not configured, ensure that public access is restricted to specific IP addresses or virtual networks.',
    recommended_action: 'Modify storage accounts and configure private endpoints or restrict public access to specific networks.',
    link: 'https://learn.microsoft.com/en-us/azure/storage/common/storage-private-endpoints',
    apis: ['storageAccounts:list'],
    realtime_triggers: ['microsoftstorage:storageaccounts:write', 'microsoftstorage:storageaccounts:delete', 'microsoftnetwork:privateendpoints:write', 'microsoftstorage:storageaccounts:privateendpointconnections:write'],
    settings: {
        check_selected_networks: {
            name: 'Evaluate Selected Networks',
            description: 'Checks if specific IP addresses or virtual networks are set to restrict Storage Account access when private endpoints are not configured.',
            regex: '^(true|false)$',
            default: false,
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        let config = {
            check_selected_networks: settings.check_selected_networks || this.settings.check_selected_networks.default
        };

        async.each(locations.storageAccounts, function(location, rcb) {
            var storageAccount = helpers.addSource(cache, source,
                ['storageAccounts', 'list', location]);

            if (!storageAccount) return rcb();

            if (storageAccount.err || !storageAccount.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Storage Accounts: ' + helpers.addError(storageAccount), location);
                return rcb();
            }

            if (!storageAccount.data.length) {
                helpers.addResult(results, 0, 'No storage accounts found', location);
                return rcb();
            }

            for (let account of storageAccount.data) {
                if (!account.id) continue;

                if (account.privateEndpointConnections && account.privateEndpointConnections.length){
                    helpers.addResult(results, 0, 'Private endpoints are configured for the storage account', location, account.id);
                } else {
                    // Check public network access when private endpoints are not configured
                    let isPublicAccessEnabled = (account.publicNetworkAccess && account.publicNetworkAccess.toLowerCase() === 'enabled') ||
                                               (!account.publicNetworkAccess && account.networkAcls && account.networkAcls.defaultAction && account.networkAcls.defaultAction.toLowerCase() === 'allow');
                    
                    if (isPublicAccessEnabled) {
                        if (config.check_selected_networks) {
                            let hasNetworkRestrictions = false;
                            
                            if (account.networkAcls) {
                                // Check if default action is deny (meaning public access is restricted)
                                if (account.networkAcls.defaultAction && account.networkAcls.defaultAction.toLowerCase() === 'deny') {
                                    hasNetworkRestrictions = true;
                                }
                                
                                // Check if there are IP rules or virtual network rules configured
                                if ((account.networkAcls.ipRules && account.networkAcls.ipRules.length > 0) || 
                                    (account.networkAcls.virtualNetworkRules && account.networkAcls.virtualNetworkRules.length > 0)) {
                                    hasNetworkRestrictions = true;
                                }
                            }
                            
                            if (hasNetworkRestrictions) {
                                helpers.addResult(results, 0, 'Storage account is not publicly accessible', location, account.id);
                            } else {
                                helpers.addResult(results, 2, 'Storage account is publicly accessible', location, account.id);
                            }
                        } else {
                            helpers.addResult(results, 2, 'Storage account is publicly accessible', location, account.id);
                        }
                    } else {
                        helpers.addResult(results, 0, 'Storage account is not publicly accessible', location, account.id);
                    }
                }
            }
            
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
