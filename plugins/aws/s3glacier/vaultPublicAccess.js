var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Glacier Vault Public Access',
    category: 'Glacier',
    domain: 'Storage',
    description: 'Ensure that S3 Glacier Vault public access block is enabled for the account.',
    more_info: 'Blocking S3 Glacier Vault public access at the account level ensures objects are not accidentally exposed.',
    recommended_action: 'Add access policy for the S3 Glacier Vault to block public access for the AWS account.',
    link: 'https://docs.aws.amazon.com/amazonglacier/latest/dev/access-control-overview.html',
    apis: ['Glacier:listVaults', 'Glacier:getVaultAccessPolicy', 'STS:getCallerIdentity'],
    settings: {
        glacier_vault_policy_condition_keys: {
            name: 'S3 Glacier Vault Policy Allowed Condition Keys',
            description: 'Comma separated list of AWS IAM condition keys that should be allowed i.e. aws:SourceAccount, aws:SourceArn',
            regex: '^.*$',
            default: 'aws:PrincipalArn,aws:PrincipalAccount,aws:PrincipalOrgID,aws:SourceOwner,aws:SourceArn,aws:SourceAccount'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var config = {
            glacier_vault_policy_condition_keys: settings.glacier_vault_policy_condition_keys || this.settings.glacier_vault_policy_condition_keys.default
        };
        config.glacier_vault_policy_condition_keys = config.glacier_vault_policy_condition_keys.replace(/\s/g, '');
        var allowedConditionKeys = config.glacier_vault_policy_condition_keys.split(',');


        regions.glacier.forEach(region => {
            const listVaults = helpers.addSource(cache, source,
                ['glacier', 'listVaults', region]);

            if (!listVaults) return;

            if (listVaults.err || !listVaults.data) {
                helpers.addResult(results, 3, `Unable to list S3 Glacier vaults: ${helpers.addError(listVaults)}`, region);
                return;
            }

            if (!listVaults.data.length) {
                helpers.addResult(results, 0, 'No S3 Glacier vaults found', region);
                return;
            }

            for (let vault of listVaults.data) {
                if (!vault.VaultName) continue;

                let resource = vault.VaultARN;

                const getVaultAccessPolicy = helpers.addSource(cache, source,
                    ['glacier', 'getVaultAccessPolicy', region, vault.VaultName]);

                if (getVaultAccessPolicy && getVaultAccessPolicy.err && getVaultAccessPolicy.err.code &&
                    getVaultAccessPolicy.err.code == 'ResourceNotFoundException') {
                    helpers.addResult(results, 0,
                        'S3 Glacier vault does not have any policy attached', region, resource);
                    continue;
                }

                if (!getVaultAccessPolicy || getVaultAccessPolicy.err || !getVaultAccessPolicy.data) {
                    helpers.addResult(results, 3, `Unable to get vault policy: ${helpers.addError(getVaultAccessPolicy)}`, region, resource);
                    continue;
                }

                var statements = (getVaultAccessPolicy.data.policy && getVaultAccessPolicy.data.policy.Policy) ?
                    helpers.normalizePolicyDocument(getVaultAccessPolicy.data.policy.Policy) : [];

                if (!statements || !statements.length) {
                    helpers.addResult(results, 0,
                        'S3 Glacier vault policy does not contain any statements',
                        region, resource);
                    continue;
                }

                let actions = [];
                for (let statement of statements) {
                    var effectEval = (statement.Effect && statement.Effect == 'Allow' ? true : false);

                    // Evaluates whether the principal is open to everyone/anonymous
                    var principalEval = helpers.globalPrincipal(statement.Principal);

                    // Evaluates whether condition is scoped or global
                    let scopedCondition;
                    if (statement.Condition) scopedCondition = helpers.isValidCondition(statement, allowedConditionKeys, helpers.IAM_CONDITION_OPERATORS, false, accountId);

                    if (!scopedCondition && principalEval && effectEval) {
                        if (statement.Action && typeof statement.Action === 'string') {
                            if (actions.indexOf(statement.Action) === -1) {
                                actions.push(statement.Action);
                            }
                        } else if (statement.Action && statement.Action.length) {
                            for (var a in statement.Action) {
                                if (actions.indexOf(statement.Action[a]) === -1) {
                                    actions.push(statement.Action[a]);
                                }
                            }
                        }
                    }
                }

                if (actions.length) {
                    helpers.addResult(results, 2,
                        'S3 Glacoer vault policy allows global access to the action(s): ' + actions,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'S3 Glacoer vault policy does not allow global access',
                        region, resource);
                }
            }
        });

        callback(null, results, source);
    }
};