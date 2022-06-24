var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache idle Cluster Status',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Identify ElastiCache clusters having CPU utilization below defined threshold within last 24 hours (idle clusters).',
    more_info: 'Idle Amazon ElastiCache cache cluster nodes represent a good candidate to reduce your monthly AWS costs and avoid accumulating unnecessary usage charges.',
    link: 'https://aws.amazon.com/elasticache/features/',
    recommended_action: 'Identify and remove idle ElastiCache clusters',
    apis: ['ElastiCache:describeCacheClusters', 'CloudWatch:getEcMetricStatistics'],
    settings: {
        elasticache_idle_node_percentage: {
            name: 'ElastiCache Idle Node Average Percentage',
            description: 'A percentage value for cluster CPU utilization under which cluster is considered idle i.e. 2.50',
            regex: '^(100(\.0{1,2})?|[1-9]?\d(\.\d{1,2})?)$', // eslint-disable-line
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var elasticache_idle_node_percentage = settings.elasticache_idle_node_percentage || this.settings.elasticache_idle_node_percentage.default; 

        if (!elasticache_idle_node_percentage.length) return callback(null, results, source);

        elasticache_idle_node_percentage = parseFloat(elasticache_idle_node_percentage);

        async.each(regions.elasticache, function(region, rcb) {
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(
                    results, 3,
                    `Unable to query for ElastiCache cluster: ${helpers.addError(describeCacheClusters)}`, region);
                return rcb();
            }

            if (!describeCacheClusters.data.length){
                helpers.addResult(results, 0, 'No ElastiCache cluster found', region);
                return rcb();
            }

            describeCacheClusters.data.forEach(cluster => {
                if (!cluster.ARN) return;

                var resource = cluster.ARN;             
                var getEcMetricStatistics = helpers.addSource(cache, source,
                    ['cloudwatch', 'getEcMetricStatistics', region, cluster.CacheClusterId]);
               
                if (!getEcMetricStatistics || getEcMetricStatistics.err ||
                    !getEcMetricStatistics.data || !getEcMetricStatistics.data.Datapoints) {
                    helpers.addResult(results, 3,
                        `Unable to query for ElastiCache cluster metric stats: ${helpers.addError(getEcMetricStatistics)}`, region, resource);
                    return;
                }

                if (!getEcMetricStatistics.data.Datapoints.length) {
                    helpers.addResult(results, 0,
                        'ElastiCache cluster metric statistics are not configured', region, resource);
                } else {
                    const isIdle = getEcMetricStatistics.data.Datapoints.every(datapoint => datapoint.Average < elasticache_idle_node_percentage);
                    const idleHours = getEcMetricStatistics.data.Datapoints.length;

                    const status = isIdle ? 2 : 0;
                    helpers.addResult(results, status,
                        `ElastiCache cluster is ${isIdle ? 'idle since ' + idleHours + ' hours': 'not idle'}`, region, resource);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }   
};