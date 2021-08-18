var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch CMK Encrypted',
    category: 'ES',
    description: 'Ensure AWS ElasticSearch domains are encrypted with KMS Customer Master Keys.',
    more_info: 'ElasticSearch domains should be encrypted with  KMS Customer Master Key (CMK) to ensure data is secured. Customer keys should be used to ensure control over the encryption seed data.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/encryption-at-rest.html',
    recommended_action: 'Ensure encryption-at-rest is enabled for all ElasticSearch domains with KMS Customer Master Keys.',
    apis: ['ES:listDomainNames', 'ES:describeElasticsearchDomain'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    'Unable to query for ES domains: ' + helpers.addError(listDomainNames), region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(function(domain){
                var describeElasticsearchDomain = helpers.addSource(cache, source,
                    ['es', 'describeElasticsearchDomain', region, domain.DomainName]);

                if (!describeElasticsearchDomain ||
                    describeElasticsearchDomain.err ||
                    !describeElasticsearchDomain.data ||
                    !describeElasticsearchDomain.data.DomainStatus) {
                    helpers.addResult(
                        results, 3,
                        'Unable to query for ES domain config: ' + helpers.addError(describeElasticsearchDomain), region);
                } else {
                    var localDomain = describeElasticsearchDomain.data.DomainStatus;

                    if (localDomain.EncryptionAtRestOptions &&
                        localDomain.EncryptionAtRestOptions.Enabled &&
                        localDomain.EncryptionAtRestOptions.KmsKeyId) {
                        if (localDomain.EncryptionAtRestOptions.KmsKeyId === '(Default) aws/es'){
                            helpers.addResult(results, 2,
                                `ES domain "${domain.DomainName}" is not using Customer Master Key for encryption`,
                                region, localDomain.ARN);
                        } else {
                            helpers.addResult(results, 0,
                                `ES domain "${domain.DomainName}" is using Customer Master Key for encryption`,
                                region, localDomain.ARN);
                        }
                    } else {
                        helpers.addResult(results, 2,
                            'ES domain is not configured to use encryption at rest', region, localDomain.ARN);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};
