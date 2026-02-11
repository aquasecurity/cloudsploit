const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Cosmos DB Public Access Disabled',
    category: 'Cosmos DB',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that Microsoft Azure Cosmos DB accounts are configured to deny public access.',
    more_info: 'Microsoft Azure Cosmos DB accounts should not be accessible from internet and only be accessed from within a VNET.',
    link: 'https://learn.microsoft.com/en-us/azure/cosmos-db/how-to-configure-firewall',
    recommended_action: 'Modify firewall and the virtual network configuration for your Cosmos DB accounts to provide access to selected networks.',
    apis: ['databaseAccounts:list'],
    realtime_triggers: ['microsoftdocumentdb:databaseaccounts:write','microsoftdocumentdb:databaseaccounts:write'],
    
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        function isOpenCidrRange(cidr) {
            if (!cidr || typeof cidr !== 'string') return false;
            
            const trimmed = cidr.trim();
            // Check for exact matches that indicate fully open access
            return trimmed === '0.0.0.0/0' || 
                   trimmed === '::/0' || 
                   trimmed === '0.0.0.0';
        }

        async.each(locations.databaseAccounts, function(location, rcb) {
            var databaseAccounts = helpers.addSource(cache, source,
                ['databaseAccounts', 'list', location]);

            if (!databaseAccounts) return rcb();

            if (databaseAccounts.err || !databaseAccounts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Cosmos DB accounts: ' + helpers.addError(databaseAccounts), location);
                return rcb();
            }

            if (!databaseAccounts.data.length) {
                helpers.addResult(results, 0, 'No Cosmos DB accounts found', location);
                return rcb();
            }

            
            databaseAccounts.data.forEach(account => {
                if (!account.id) return;

                const isPublicAccessEnabled = account.publicNetworkAccess &&
                    account.publicNetworkAccess.toLowerCase() === 'enabled';

                if (!isPublicAccessEnabled) {
                    helpers.addResult(results, 0,
                        'Cosmos DB account has public network access disabled', location, account.id);
                    return;
                }

                const hasIpRules = account.ipRules && account.ipRules.length > 0;
                const hasVnetRules = account.virtualNetworkRules && account.virtualNetworkRules.length > 0;
                let hasOpenCidr = false;
                if (hasIpRules) {
                    for (let rule of account.ipRules) {
                        if (isOpenCidrRange(rule.ipAddressOrRange)) {
                            hasOpenCidr = true;
                            break;
                        }
                    }
                }

                if (hasOpenCidr) {
                    helpers.addResult(results, 2,
                        'Cosmos DB account allows unrestricted public access', location, account.id);
                    return;
                }

                if (hasIpRules || hasVnetRules || account.isVirtualNetworkFilterEnabled === true) {
                    helpers.addResult(results, 0,
                        'Cosmos DB account denies public access', location, account.id);
                    return;
                }


                helpers.addResult(results, 2,
                    'Cosmos DB account allows public access', location, account.id);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
