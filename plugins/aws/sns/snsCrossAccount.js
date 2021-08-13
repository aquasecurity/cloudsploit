var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SNS Cross Account Access',
    category: 'SNS',
    description: 'Ensures SNS policies disallow cross-account access',
    more_info: 'SNS topic policies should be carefully restricted to to subscribe or send messages. Topic policies can be used to limit these privileges.',
    recommended_action: 'Update the SNS policy to prevent access from external accounts.',
    link: 'https://docs.aws.amazon.com/sns/latest/dg/sns-using-identity-based-policies.html',
    apis: ['SNS:listTopics', 'SNS:getTopicAttributes', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        sns_whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        sns_whitelist_aws_organization_accounts: {
            name: 'Whitelist All AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        },
        sns_topic_policy_condition_keys: {
            name: 'SNS Topic Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount,aws:PrincipalArn',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceAccount,aws:SourceArn,aws:SourceOwner'
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            sns_whitelisted_aws_account_principals : settings.sns_whitelisted_aws_account_principals || this.settings.sns_whitelisted_aws_account_principals.default,
            sns_whitelist_aws_organization_accounts: settings.sns_whitelist_aws_organization_accounts || this.settings.sns_whitelist_aws_organization_accounts.default,
            sns_topic_policy_condition_keys: settings.sns_topic_policy_condition_keys || this.settings.sns_topic_policy_condition_keys.default,
        };
        var allowedConditionKeys = config.sns_topic_policy_condition_keys.split(',');
        var whitelistOrganization = (config.sns_whitelist_aws_organization_accounts == 'true');

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);

        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', acctRegion]);
    
            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, acctRegion);
                return callback(null, results, source);
            }

            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }

        async.each(regions.sns, function(region, rcb){
            var listTopics = helpers.addSource(cache, source,
                ['sns', 'listTopics', region]);

            if (!listTopics) return rcb();

            if (listTopics.err || !listTopics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SNS topics: ' + helpers.addError(listTopics), region);
                return rcb();
            }

            if (!listTopics.data.length) {
                helpers.addResult(results, 0, 'No SNS topics found', region);
                return rcb();
            }

            async.each(listTopics.data, function(topic, cb){
                if (!topic.TopicArn) return cb();

                var getTopicAttributes = helpers.addSource(cache, source,
                    ['sns', 'getTopicAttributes', region, topic.TopicArn]);

                if (!getTopicAttributes ||getTopicAttributes.err || !getTopicAttributes.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SNS topic for attributes: ' + helpers.addError(getTopicAttributes),
                        region, topic.TopicArn);
                    return cb();
                }

                if (!getTopicAttributes.data.Attributes ||
                    !getTopicAttributes.data.Attributes.Policy) {
                    helpers.addResult(results, 0,
                        'The SNS topic does not have a policy attached.',
                        region, topic.TopicArn);
                    return cb();
                }

                try {
                    var policy = JSON.parse(getTopicAttributes.data.Attributes.Policy);
                } catch (e) {
                    helpers.addResult(results, 3,
                        'The SNS topic policy is not valid JSON.',
                        region, topic.TopicArn);

                    return cb();
                }

                var crossAccountActions = [];

                var statements = helpers.normalizePolicyDocument(policy);

                for (var statement of statements) {
                    if (!statement.Effect || statement.Effect !== 'Allow') continue;
                    if (!statement.Principal) continue;

                    let conditionalPrincipals = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId);
                    if (helpers.crossAccountPrincipal(statement.Principal, accountId) ||
                        (conditionalPrincipals && conditionalPrincipals.length)) {
                        let crossAccountPrincipals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);

                        if (conditionalPrincipals && conditionalPrincipals.length) {
                            conditionalPrincipals.forEach(conPrincipal => {
                                if (!conPrincipal.includes(accountId)) crossAccountPrincipals.push(conPrincipal);
                            });
                        }

                        if (!crossAccountPrincipals.length) continue;

                        let crossAccount = false;
                        let orgAccount;

                        for (let principal of crossAccountPrincipals) {
                            if (config.sns_whitelisted_aws_account_principals.includes(principal)) continue;

                            if (whitelistOrganization) {
                                orgAccount = organizationAccounts.find(account => principal.includes(account));
                                if (orgAccount) continue;
                            }
                            crossAccount = true;
                            break;
                        }

                        if (crossAccount) {
                            for (let a in statement.Action) {
                                if (crossAccountActions.indexOf(statement.Action[a]) === -1) {
                                    crossAccountActions.push(statement.Action[a]);
                                }
                            }
                        }
                    }
                }

                if (crossAccountActions.length) {
                    helpers.addResult(results, 2,
                        'SNS topic policy allows cross-account access to the action(s): ' + crossAccountActions,
                        region, topic.TopicArn);
                } else {
                    helpers.addResult(results, 0,
                        'SNS topic policy does not allow cross-account access',
                        region, topic.TopicArn);
                }

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};