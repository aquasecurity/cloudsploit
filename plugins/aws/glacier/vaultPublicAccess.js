var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'S3 Glacier Vault Public Access',
    category: 'S3',
    description: 'Ensure that S3 Glacier Vault public access block is enabled for the account.',
    more_info: 'Blocking S3 Glacier Vault public access at the account level ensures objects are not accidentally exposed.',
    recommended_action: 'Add access policy for the S3 Glacier Vault to block public access for the AWS account.',
    link: 'https://docs.aws.amazon.com/amazonglacier/latest/dev/access-control-overview.html',
    apis: ['Glacier:listVaults', 'Glacier:getVaultAccessPolicy', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {

        const results = [];
        const source = {};
        const regions = helpers.regions(settings);

        regions.glacier.forEach(region => {
            const listVaults = helpers.addSource(cache, source,
                ['glacier', 'listVaults', region]);

            if (!listVaults) return;
            if (listVaults.err || !listVaults.data) {
                helpers.addResult(results, 3, `Unable to list S3 Glacier vaults: ${helpers.addError(listVaults)}`, region);
                return;
            }

            if (!listVaults.data.length) {
                helpers.addResult(results, 0, 'No S3 glacier vault exists');
                return;
            }

            listVaults.data.forEach(vault => {
                const getVaultPolicy = helpers.addSource(cache, source,
                    ['glacier', 'getVaultAccessPolicy', region, vault.VaultName]);

                if (!getVaultPolicy) return;
                if (getVaultPolicy.err || !getVaultPolicy.data) {
                    helpers.addResult(results, 3, `Unable to get vault policy: ${helpers.addError(getVaultPolicy)}`, region, vault.VaultARN);
                    return;
                }

                if (!getVaultPolicy.data.policy && getVaultPolicy.data.policy.Policy) {
                    helpers.addResult(results, 3, 'Policy does not exist', region, vault.VaultARN);
                    return;
                }

                try {
                    const policyJson = JSON.parse(getVaultPolicy.data.policy.Policy);

                    if (!policyJson || !policyJson.Statement) {
                        helpers.addResult(results, 3,
                            'Error querying for vault policy. Policy JSON is invalid or does not contain valid statements',
                            region, vault.VaultARN);
                    } else if (!policyJson.Statement.length) {
                        helpers.addResult(results, 0,
                            'Vault policy does not contain any statements',
                            region, vault.VaultARN);
                    } else {
                        var policyMessage = [];
                        var policyResult = 0;

                        for (var s in policyJson.Statement) {
                            var statement = policyJson.Statement[s];

                            if (statement.Effect && statement.Effect === 'Allow') {
                                if (statement.Principal) {
                                    var starPrincipal = false;

                                    if (typeof statement.Principal === 'string') {
                                        if (statement.Principal === '*') {
                                            starPrincipal = true;
                                        }
                                    } else if (typeof statement.Principal === 'object') {
                                        if (statement.Principal.Service &&
                                            statement.Principal.Service === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.AWS &&
                                            statement.Principal.AWS === '*') {
                                            starPrincipal = true;
                                        } else if (statement.Principal.length &&
                                            statement.Principal.indexOf('*') > -1) {
                                            starPrincipal = true;
                                        }
                                    }

                                    if (starPrincipal) {
                                        if (statement.Condition) {
                                            if (policyResult < 1) policyResult = 0;
                                            policyMessage.push('Principal * allowed to conditionally perform: ' + statement.Action);
                                        } else {
                                            if (policyResult < 2) policyResult = 2;
                                            policyMessage.push('Principal * allowed to perform: ' + statement.Action);
                                        }
                                    }
                                }
                            }
                        }

                        if (!policyMessage.length) {
                            helpers.addResult(results, 0,
                                'Vault policy does not contain any insecure allow statements',
                                region, vault.VaultARN);
                        } else {
                            helpers.addResult(results, policyResult,
                                policyMessage.join(' '),
                                region, vault.VaultARN);
                        }
                    }
                } catch (err) {
                    helpers.addResult(results, 3,
                        'Error querying for vault policy. Policy JSON could not be parsed.',
                        region, vault.VaultARN);
                }
            });
        });

        callback(null, results, source);
    }
};