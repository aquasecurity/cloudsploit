var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElasticSearch Cluster Status',
    category: 'ES',
    domain: 'Databases',
    description: 'Ensure that ElasticSearch clusters are healthy, i.e status is green.',
    more_info: 'Unhealthy Amazon ES clusters with the status set to "Red" is crucial for availability of ElasticSearch applications.',
    link: 'https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/cloudwatch-alarms.html',
    recommended_action: 'Configure alarms to send notification if cluster status remains red for more than a minute.',
    apis: ['ES:listDomainNames', 'CloudWatch:getEsMetricStatistics', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var accRegion = helpers.defaultRegion(settings);
        var accountId =  helpers.addSource(cache, source, ['sts', 'getCallerIdentity', accRegion, 'data']);
        var awsOrGov = helpers.defaultPartition(settings);

        async.each(regions.es, function(region, rcb) {
            var listDomainNames = helpers.addSource(cache, source,
                ['es', 'listDomainNames', region]);

            if (!listDomainNames) return rcb();

            if (listDomainNames.err || !listDomainNames.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for ES domains: ${helpers.addError(listDomainNames)}`, region);
                return rcb();
            }

            if (!listDomainNames.data.length){
                helpers.addResult(results, 0, 'No ES domains found', region);
                return rcb();
            }

            listDomainNames.data.forEach(domain => {
                if (!domain.DomainName) return;                
                
                const resource = `arn:${awsOrGov}:es:${region}:${accountId}:domain/${domain.DomainName}`;
                var getMetricStats = helpers.addSource(cache, source,
                    ['cloudwatch', 'getEsMetricStatistics', region, domain.DomainName]);
               
                if (!getMetricStats || getMetricStats.err || !getMetricStats.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for ES domain metric stat: ${helpers.addError(getMetricStats)}`, region, resource);
                    return;
                }
                const data = getMetricStats.data.Datapoints.find(datapoint => datapoint.Maximum && datapoint.Maximum >= 1);
                const status = data ? 2 : 0;
                helpers.addResult(results, status,
                    `ES Domain is ${data ? 'unhealthy': 'healthy'}`, region, resource);
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }   
};