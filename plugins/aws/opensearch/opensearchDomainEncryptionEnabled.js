var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'OpenSearch Encryption Enabled',
    category: 'OpenSearch',
    domain: 'Databases',
    severity: 'High',
    description: 'Ensure that AWS OpenSearch domains have encryption enabled.',
    more_info: 'OpenSearch domains should be encrypted to ensure that data is secured.',
    link: 'https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html',
    recommended_action: 'Ensure encryption-at-rest is enabled for all OpenSearch domains.',
    apis: ['OpenSearch:listDomainNames', 'OpenSearch:describeDomain', 'KMS:listKeys', 'KMS:describeKey', 'STS:getCallerIdentity'],
    settings: {
        es_encryption_level: {
            name: 'OpenSearch Domain Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awskms',
        }
    },
    realtime_triggers: ['opensearch:CreateDomain', 'opensearch:UpdateDomainConfig', 'opensearch:DeleteDomain'], 
    
    run: function(cache, settings, callback) {
        var config = {
            desiredEncryptionLevelString: settings.es_encryption_level || this.settings.es_encryption_level.default
        };
        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

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
                    helpers.addResult(
                        results, 3,
                        'Unable to query for OpenSearch domain config: ' + helpers.addError(describeDomain), region, resource);
                } else {
                    if (describeDomain.data.DomainStatus &&
                        describeDomain.data.DomainStatus.EncryptionAtRestOptions &&
                        describeDomain.data.DomainStatus.EncryptionAtRestOptions.Enabled &&
                        describeDomain.data.DomainStatus.EncryptionAtRestOptions.KmsKeyId) {
                        var kmsKeyId = describeDomain.data.DomainStatus.EncryptionAtRestOptions.KmsKeyId.split('/')[1];
                        var describeKey = helpers.addSource(cache, source,
                            ['kms', 'describeKey', region, kmsKeyId]);

                        if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                            helpers.addResult(results, 3,
                                `Unable to query KMS key: ${helpers.addError(describeKey)}`, region, kmsKeyId);
                            return;
                        }

                        var currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                        var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `OpenSearch domain has encryption at-rest enabled for data at encryption level ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `OpenSearch domain has encryption at-rest enabled for data at encryption level ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                                region, resource);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'OpenSearch domain is not configured to use encryption at rest', region, resource);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};
