var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Domain Cross Account access',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'Critical',
    description: 'Ensures that only trusted accounts have access to OpenSearch domains.',
    more_info: 'Allowing unrestricted access of OpenSearch clusters will cause data leaks and data loss. This can be prevented by restricting access only to the trusted entities by implementing the appropriate access policies.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cross-cluster-search.html',
    recommended_action: 'Restrict the access to OpenSearch clusters to allow only trusted accounts.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        os_whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        os_whitelisted_aws_account_principals_regex: {
            name: 'Whitelisted AWS Account Principals Regex',
            description: 'If set, plugin will compare cross account principals against this regex instead of otherwise given comma-separated list' +
                'Example regex: ^arn:aws:iam::(111111111111|222222222222|):.+$',
            regex: '^.*$',
            default: ''
        },
        os_whitelist_aws_organization_accounts: {
            name: 'Whitelist AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        },
        os_policy_condition_keys: {
            name: 'OpenSearch Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount,aws:PrincipalArn',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceAccount,aws:SourceArn,aws:SourceOwner'
        },
    },
    realtime_triggers: ['opensearch:CreateDomain','opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 

    run: function(cache, settings, callback) {
        var config= {
            os_whitelisted_aws_account_principals : settings.os_whitelisted_aws_account_principals || this.settings.os_whitelisted_aws_account_principals.default,
            os_whitelisted_aws_account_principals_regex : settings.os_whitelisted_aws_account_principals_regex || this.settings.os_whitelisted_aws_account_principals_regex.default,
            os_whitelist_aws_organization_accounts: settings.os_whitelist_aws_organization_accounts || this.settings.os_whitelist_aws_organization_accounts.default,
            os_policy_condition_keys: settings.os_policy_condition_keys || this.settings.os_policy_condition_keys.default,
        };
        var allowedConditionKeys = config.os_policy_condition_keys.split(',');
        var makeRegexBased = (config.os_whitelisted_aws_account_principals_regex.length) ? true : false;
        var whitelistOrganization = (config.os_whitelist_aws_organization_accounts == 'true'); 
        config.os_whitelisted_aws_account_principals_regex = new RegExp(config.os_whitelisted_aws_account_principals_regex);
        

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', regions.default, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);
        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', defaultRegion]);

            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, defaultRegion);
                return callback(null, results, source);
            }
            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }

        async.each(regions.opensearch, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['opensearch', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();
            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for OpenSearch domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No OpenSearch domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(domain => {
                if (!domain.DomainName) return;

                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;

                var describeDomain = helpers.addSource(cache, source,
                    ['opensearch', 'describeDomain', region, domain.DomainName]);

                if (!describeDomain ||
                    describeDomain.err ||
                    !describeDomain.data ||
                    !describeDomain.data.DomainStatus) {
                    helpers.addResult(results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeDomain), region, resource);
                } else {
                    var localDomain = describeDomain.data.DomainStatus;
                   
                    if (!localDomain.AccessPolicies)  {                        
                        helpers.addResult(results, 0,
                            'OpenSearch domain does not have access policy defined', region, resource);
                        return;
                    }
                           
                    var statements = helpers.normalizePolicyDocument(localDomain.AccessPolicies);
        
                    if (!statements){
                        helpers.addResult(results, 0, 'No statement exists for the policy', region, resource);
                        return;
                    }

                    var restrictedAccountPrincipals = [];
                    var crossAccountEs = false;
        
                    statements.forEach(statement => {
                        if (!statement.Principal) return;
    
                        let conditionalPrincipals = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId, settings);
                        if (helpers.crossAccountPrincipal(statement.Principal, accountId, undefined , settings) ||
                            (conditionalPrincipals && conditionalPrincipals.length)) {
                            let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true, settings);

                            if (conditionalPrincipals && conditionalPrincipals.length) {
                                conditionalPrincipals.forEach(conPrincipal => {
                                    if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
                                });
                            }

                            if (!crossAccountPrincipals.length) return;
                            crossAccountEs = true;
                            crossAccountPrincipals.forEach(principal => {
                                if (whitelistOrganization) {
                                    if (organizationAccounts.find(account => principal.includes(account))) return;
                                }
                                if (makeRegexBased) {
                                    if (!config.os_whitelisted_aws_account_principals_regex.test(principal) &&
                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                                } else if (!config.os_whitelisted_aws_account_principals.includes(principal) &&
                                        !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                            });
                        }
                    });

                    if (crossAccountEs && !restrictedAccountPrincipals.length) {
                        helpers.addResult(results, 0,
                            'OpenSearch domain contains trusted account principals only', region, resource);
                    } else if (crossAccountEs) {
                        helpers.addResult(results, 2,
                            `OpenSearch domain contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`, region,resource);
                    } else {
                        helpers.addResult(results, 0,
                            'OpenSearch domain does not contain cross-account policy statement', region, resource);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};
