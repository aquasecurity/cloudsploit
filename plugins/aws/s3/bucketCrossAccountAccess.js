var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Bucket Cross Organization Access',
    category: 'S3',
    description: 'Ensure that S3 buckets are configured only to allow access to whitelisted AWS account principals.',
    more_info: 'S3 bucket policy should be configured to allow access only to whitelisted/trusted cross-account principals.',
    recommended_action: 'Add bucket policy to manage cross-account access.',
    link: 'https://aws.amazon.com/premiumsupport/knowledge-center/cross-account-access-s3/',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy', 'STS:getCallerIdentity', 'Organizations:listAccounts'],
    settings: {
        whitelisted_aws_account_principals: {
            name: 'Whitelisted AWS Account Principals',
            description: 'A comma-separated list of trusted cross account principals',
            regex: '^.*$',
            default: ''
        },
        whitelisted_aws_account_principals_regex: {
            name: 'Whitelisted AWS Account Principals Regex',
            description: 'If set, plugin will compare cross account principals against this regex instead of otherwise given comma-separated list' +
                'Example regex: ^arn:aws:iam::(111111111111|222222222222|):.+$',
            regex: '^.*$',
            default: ''
        },
        iam_whitelist_aws_organization_accounts: {
            name: 'Whitelist AWS Organization Accounts',
            description: 'If true, trust all accounts in current AWS organization',
            regex: '^(true|false)$',
            default: 'false'
        }
    },
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. If PCI-restricted data is stored in S3, ' +
             'those buckets should not enable global user access.'
    },


    run: function(cache, settings, callback) {
        var config= {
            whitelisted_aws_account_principals : settings.whitelisted_aws_account_principals || this.settings.whitelisted_aws_account_principals.default,
            whitelisted_aws_account_principals_regex : settings.whitelisted_aws_account_principals_regex || this.settings.whitelisted_aws_account_principals_regex.default,
            iam_whitelist_aws_organization_accounts: settings.iam_whitelist_aws_organization_accounts || this.settings.iam_whitelist_aws_organization_accounts.default
        };
        var makeRegexBased = (config.whitelisted_aws_account_principals_regex.length) ? true : false;
        var whitelistOrganization = (config.iam_whitelist_aws_organization_accounts == 'true'); 
        config.whitelisted_aws_account_principals_regex = new RegExp(config.whitelisted_aws_account_principals_regex);
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', region, 'data']);

        var listBuckets = helpers.addSource(cache, source,
            ['s3', 'listBuckets', region]);

        if (!listBuckets) return callback(null, results, source);

        if (listBuckets.err || !listBuckets.data) {
            helpers.addResult(results, 3,
                'Unable to query for S3 buckets: ' + helpers.addError(listBuckets));
            return callback(null, results, source);
        }

        if (!listBuckets.data.length) {
            helpers.addResult(results, 0, 'No S3 buckets to check');
            return callback(null, results, source);
        }

        let organizationAccounts = [];
        if (whitelistOrganization) {
            var listAccounts = helpers.addSource(cache, source,
                ['organizations', 'listAccounts', region]);
            
            if (!listAccounts || listAccounts.err || !listAccounts.data) {
                helpers.addResult(results, 3,
                    `Unable to query organization accounts: ${helpers.addError(listAccounts)}`, region);
                return callback(null, results, source);
            }

            organizationAccounts = helpers.getOrganizationAccounts(listAccounts, accountId);
        }

        listBuckets.data.forEach(bucket => {
            if (!bucket.Name) return;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);
            
            if (!getBucketPolicy.data){
                helpers.addResult(results, 2, 'No bucket policy exists', 'global', bucketResource);
                return;
            }
            
            var statements = helpers.normalizePolicyDocument(getBucketPolicy.data.Policy);
            
            if (!statements){
                helpers.addResult(results, 3, 'No statement exists for the policy', 'global', bucketResource);
                return;
            }
            var restrictedAccountPrincipals = [];
            var crossAccountBucket = false;
            
            statements.forEach(statement => {
                if (statement.Principal && helpers.crossAccountPrincipal(statement.Principal, accountId)) {
                    crossAccountBucket = true;
                    var principals = helpers.crossAccountPrincipal(statement.Principal, accountId, true);
                    if (principals.length) {
                        principals.forEach(principal => {
                            if (whitelistOrganization) {
                                if (organizationAccounts.find(account => principal.includes(account))) return;
                            }
                            if (makeRegexBased) {
                                if (!config.whitelisted_aws_account_principals_regex.test(principal) &&
                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                            } else if (!config.whitelisted_aws_account_principals.includes(principal) &&
                                    !restrictedAccountPrincipals.includes(principal)) restrictedAccountPrincipals.push(principal);
                        });
                    }
                    return;
                }
            });
            if (crossAccountBucket && !restrictedAccountPrincipals.length) {
                helpers.addResult(results, 0,
                    `Bucket "${bucket.Name}" contains trusted account principals only`,
                    'global', bucketResource);
            } else if (crossAccountBucket) {
                helpers.addResult(results, 2,
                    `Bucket "${bucket.Name}" contains these untrusted account principals: ${restrictedAccountPrincipals.join(', ')}`,
                    'global', bucketResource);
            } else {
                helpers.addResult(results, 2,
                    `Bucket "${bucket.Name}" does not contain cross-account policy statement`,
                    'global', bucketResource);
            }
        });
        callback(null, results, source);
    }    
};
