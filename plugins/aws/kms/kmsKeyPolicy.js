var async = require('async');
var helpers = require('../../../helpers/aws');
module.exports = {
    title: 'KMS Key Policy',
    category: 'KMS',
    description: 'Validates the KMS key policy to ensure least-privilege access.',
    more_info: 'KMS key policies should be designed to limit the number of users who can perform encrypt and decrypt operations. Each application should use its own key to avoid over exposure.',
    recommended_action: 'Modify the KMS key policy to remove any wildcards and limit the number of users and roles that can perform encrypt and decrypt operations using the key.',
    link: 'http://docs.aws.amazon.com/kms/latest/developerguide/key-policies.html',
    apis: ['KMS:listKeys', 'STS:getCallerIdentity', 'KMS:getKeyPolicy', 'KMS:describeKey'],
    settings: {
        kms_key_policy_max_user_count: {
            name: 'KMS Key Policy Max User Count',
            description: 'Return a failing result when KMS key policies contain more than this many trusted users',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: 10
        },
        kms_key_policy_max_third_parties_count: {
            name: 'KMS Key Policy Max Third Parties Count',
            description: 'Return a warning result when KMS key policies contain more than this many trusted third parties',
            regex: '^[0-9]{0,3}$',
            default: 0
        },
        kms_key_policy_whitelisted_account_ids: {
            name: 'KMS Key Policy Whitelisted Account IDs',
            description: 'A comma-delimited list of known third-party AWS account IDs that should be trusted',
            regex: '^\\d{12}(?:,\\d{12})*$',
            default: ''
        },
        kms_key_policy_whitelisted_policy_ids: {
            name: 'KMS Key Policy Whitelisted Policy IDs',
            description: 'A comma-delimited list of known Key Policy IDs that should be trusted',
            regex: '^.{1,255}$',
            default: 'aqua-cspm'
        },
        kms_key_policy_condition_keys: {
            name: 'KMS Key Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount,kms:CallerAccount.' +
                'This setting assumes following rules:' +
                '1. As a best practice, "Deny" with "StringNotLike" and "Allow" with "StringLike" are used to prevent accidental privileged access' +
                '2. IAM condition keys which work with "Numeric" or "Date" operators are not used' +
                '3. Bool values are set to "true" with "Allow" and "false" with "Deny"',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceAccount,aws:SourceArn,kms:CallerAccount'
        },
        kms_ignore_aws_managed_keys: {
            name: 'KMS Ignore AWS-managed Keys',
            description: 'If set to true, ignore key policy for AWS-managed KMS keys',
            regex: '^(true|false)$',
            default: 'false'
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            kms_key_policy_max_user_count: settings.kms_key_policy_max_user_count || this.settings.kms_key_policy_max_user_count.default,
            kms_key_policy_max_third_parties_count: settings.kms_key_policy_max_third_parties_count || this.settings.kms_key_policy_max_third_parties_count.default,
            kms_key_policy_whitelisted_account_ids: settings.kms_key_policy_whitelisted_account_ids || this.settings.kms_key_policy_whitelisted_account_ids.default,
            kms_key_policy_whitelisted_policy_ids: settings.kms_key_policy_whitelisted_policy_ids || this.settings.kms_key_policy_whitelisted_policy_ids.default,
            kms_key_policy_condition_keys: settings.kms_key_policy_condition_keys || this.settings.kms_key_policy_condition_keys.default,
            kms_ignore_aws_managed_keys: settings.kms_ignore_aws_managed_keys || this.settings.kms_ignore_aws_managed_keys.default
        };

        if (config.kms_key_policy_whitelisted_account_ids && config.kms_key_policy_whitelisted_account_ids.length) {
            config.kms_key_policy_whitelisted_account_ids = config.kms_key_policy_whitelisted_account_ids.split(',');
        } else {
            config.kms_key_policy_whitelisted_account_ids = [];
        }

        if (config.kms_key_policy_whitelisted_policy_ids && config.kms_key_policy_whitelisted_policy_ids.length) {
            config.kms_key_policy_whitelisted_policy_ids = config.kms_key_policy_whitelisted_policy_ids.split(',');
        } else {
            config.kms_key_policy_whitelisted_policy_ids = [];
        }

        config.kms_ignore_aws_managed_keys = (config.kms_ignore_aws_managed_keys == 'true');

        var allowedConditionKeys = config.kms_key_policy_condition_keys.split(',');
        allowedConditionKeys.push('kms:CallerAccount', 'kms:ViaService');

        var custom = helpers.isCustom(settings, this.settings);
        if (config.kms_key_policy_whitelisted_account_ids.length) custom = true;

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.kms, function(region, rcb){
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data){
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            if (!listKeys.data.length){
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();
            }

            async.each(listKeys.data, function(kmsKey, kcb){
                if (config.kms_ignore_aws_managed_keys) {
                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKey.KeyId]);
                
                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3, `Unable to query for KMS Key: ${helpers.addError(describeKey)}`, region);
                        return kcb();
                    }
    
                    let keyLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
    
                    if (keyLevel == 2) {
                        helpers.addResult(results, 0,
                            'KMS key is AWS-managed', region, kmsKey.KeyArn);
                        return kcb();
                    }
                }

                var getKeyPolicy = helpers.addSource(cache, source,
                    ['kms', 'getKeyPolicy', region, kmsKey.KeyId]);

                if (!getKeyPolicy || getKeyPolicy.err || !getKeyPolicy.data){
                    helpers.addResult(results, 3,
                        'Unable to get key policy: ' + helpers.addError(getKeyPolicy),
                        region, kmsKey.KeyArn);
                    return kcb();
                }

                // Auq-CSPM keys for Remediations should be skipped.
                // The only way to distinguish these keys is the Policy Id.
                if (getKeyPolicy.data.Id &&
                    config.kms_key_policy_whitelisted_policy_ids.length &&
                    config.kms_key_policy_whitelisted_policy_ids.indexOf(getKeyPolicy.data.Id)>-1) {
                    helpers.addResult(results, 0, 'The key ' + kmsKey.KeyArn + ' is whitelisted.', region, kmsKey.KeyArn);
                    return kcb();
                }

                var found = false;
                var wildcardTrusted = 0;
                var thirdPartyTrusted = 0;

                var statements = getKeyPolicy.data.Statement;
                var totalUsers = [];

                for (var s in statements) {
                    var statement = statements[s];

                    if (!statement.Principal || !statement.Effect ||
                        statement.Effect !== 'Allow') continue;

                    var principal = statement.Principal;

                    if (!principal.AWS) continue;

                    if (typeof principal.AWS === 'string') {
                        principal.AWS = [principal.AWS];
                    }

                    if (!Array.isArray(principal.AWS)) continue;

                    var newUsers = principal.AWS.filter(function(newUser){
                        return totalUsers.filter(function(existingUser){
                            return existingUser === newUser;
                        }).length === 0;
                    });

                    totalUsers = totalUsers.concat(newUsers);

                    var conditionalCaller = null;

                    if (statement.Condition) {
                        conditionalCaller = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, true, accountId);
                    }

                    // Check for wildcards without condition
                    if (principal.AWS.indexOf('*') > -1 && !conditionalCaller) {
                        wildcardTrusted += 1;
                    } else if (conditionalCaller) {
                        for (var caller of conditionalCaller) {
                            if (caller !== accountId &&
                                config.kms_key_policy_whitelisted_account_ids.indexOf(caller) === -1) {
                                thirdPartyTrusted += 1;
                            }
                        }
                    } else if (!conditionalCaller) {
                        for (var u in principal.AWS) {
                            if (principal.AWS[u] !== '*' &&
                                principal.AWS[u].indexOf(accountId) === -1  &&
                                config.kms_key_policy_whitelisted_account_ids.indexOf(principal.AWS[u]) === -1) {
                                // Loop through whitelisted account IDs to ensure trusted account
                                // is not whitelisted by user.
                                var wlFound = false;
                                for (var i in config.kms_key_policy_whitelisted_account_ids) {
                                    if (principal.AWS[u].indexOf(config.kms_key_policy_whitelisted_account_ids[i]) > -1) {
                                        wlFound = true;
                                    }
                                }
                                if (!wlFound) thirdPartyTrusted += 1;
                            }
                        }
                    }
                }

                if (totalUsers.length > config.kms_key_policy_max_user_count) {
                    found = true;
                    helpers.addResult(results, 2, 'Key trusts ' + totalUsers.length +
                        ' users', region, kmsKey.KeyArn, custom);
                }

                if (thirdPartyTrusted > config.kms_key_policy_max_third_parties_count) {
                    found = true;
                    helpers.addResult(results, 1, 'Key trusts ' + thirdPartyTrusted +
                        ' third parties', region, kmsKey.KeyArn, custom);
                }

                if (wildcardTrusted) {
                    found = true;
                    helpers.addResult(results, 2, 'Key trusts ' + wildcardTrusted +
                        ' principals with wildcards', region, kmsKey.KeyArn, custom);
                }

                if (!found){
                    helpers.addResult(results, 0, 'Key policy is sufficient', region, kmsKey.KeyArn, custom);
                }

                kcb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};