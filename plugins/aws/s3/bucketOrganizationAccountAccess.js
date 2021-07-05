var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Bucket Cross Organization Access',
    category: 'S3',
    description: 'Ensure S3 buckets are configured only to allow access to accounts under whitelisted AWS Organizations',
    more_info: 'S3 buckets can be configured to allow the global principal to access the bucket via the bucket policy. This policy should be restricted only to accounts within whitelisted AWS organizations.',
    recommended_action: 'Add condition to restrict access to specific AWS organizations from the bucket policy statements.',
    link: '',
    apis: ['S3:listBuckets', 'S3:getBucketPolicy'],
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
        whitelisted_aws_organizations: {
            name: 'Whitelisted AWS Organizations',
            description: 'A comma-separated list of whitelisted AWS Organizations',
            regex: '^.*$',
            default: ''
        },
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
            whitelisted_aws_organizations : settings.whitelisted_aws_organizations || this.settings.whitelisted_aws_organizations.default,
        };
        var makeRegexBased = (config.whitelisted_aws_account_principals_regex.length) ? true : false;
        config.whitelisted_aws_account_principals_regex = new RegExp(config.whitelisted_aws_account_principals_regex);
        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

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

        for (var i in listBuckets.data) {
            var bucket = listBuckets.data[i];
            if (!bucket.Name) continue;

            var bucketResource = 'arn:aws:s3:::' + bucket.Name;

            var getBucketPolicy = helpers.addSource(cache, source,
                ['s3', 'getBucketPolicy', region, bucket.Name]);

            // Check the bucket policy
            if (getBucketPolicy && getBucketPolicy.err &&
                getBucketPolicy.err.code && getBucketPolicy.err.code === 'NoSuchBucketPolicy') {
                helpers.addResult(results, 2,
                    'No bucket policy found',
                    'global', bucketResource);
            } else if (!getBucketPolicy || getBucketPolicy.err ||
                       !getBucketPolicy.data || !getBucketPolicy.data.Policy) {
                helpers.addResult(results, 3,
                    'Error querying for bucket policy for bucket: ' + bucket.Name +
                    ': ' + helpers.addError(getBucketPolicy),
                    'global', bucketResource);
            } else {
                try {
                    var policyJson = JSON.parse(getBucketPolicy.data.Policy);
                    getBucketPolicy.data.Policy = policyJson;

                    if (!policyJson || !policyJson.Statement) {
                        helpers.addResult(results, 3,
                            'Error querying for bucket policy for bucket: ' + bucket.Name +
                            ': Policy JSON is invalid or does not contain valid statements.',
                            'global', bucketResource);
                    } else if (!policyJson.Statement.length) {
                        helpers.addResult(results, 0,
                            'Bucket policy does not contain any statements',
                            'global', bucketResource);
                    } else {
                        let foundOrganization = false;
                        let found = policyJson.Statement.find(statement => {
                            if (statement.Condition && statement.Condition.StringEquals && statement.Condition.StringEquals['aws:PrincipalOrgID']) {
                                foundOrganization = true;
                                const condition = statement.Condition.StringEquals['aws:PrincipalOrgID'];
                                if (typeof condition == 'string') {
                                    if (condition == '*'){
                                        return config.whitelisted_aws_organizations == '' ? true : false;
                                    } else {
                                        return config.whitelisted_aws_organizations.includes(condition);
                                    }
                                } else {
                                    return condition.some(value => config.whitelisted_aws_organizations.includes(value));
                                }
                            }
                        });

                        if (!foundOrganization) {
                            helpers.addResult(results, 2,
                                'No bucket policy found to restrict accounts to an organization',
                                'global', bucketResource);
                        } else if (found) {
                            helpers.addResult(results, 0,
                                'Bucket policy allows access to accounts existing in whitelisted organizations',
                                'global', bucketResource);
                        } else {
                            helpers.addResult(results, 2,
                                'Bucket policy allows access to accounts that do not exist in whitelisted organizations',
                                'global', bucketResource);
                        }
                    }
                } catch (e) {
                    helpers.addResult(results, 3,
                        'Error querying for bucket policy for bucket: ' + bucket.Name +
                        ': Policy JSON could not be parsed.',
                        'global', bucketResource);
                }
            }
        }
        
        callback(null, results, source);
    }
};