var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'ElastiCache Engine Versions for Redis',
    category: 'ElastiCache',
    domain: 'Databases',
    description: 'Ensure that Amazon ElastiCache clusters are using the stable latest version of Redis cache engine.',
    more_info: 'ElastiCache clusters with the latest version of Redis cache engine, You will benefit from new features and enhancements, ' +
        'Using engines prior to version 3.2.6 will not be benefited with Encryption Options, support for HIPAA compliance and much more. Also engine version 3.2.10 does not support Encryption options.',
    link: 'https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/supported-engine-versions.html',
    recommended_action: 'Upgrade the version of Redis on all ElastiCache clusters to the latest available version.',
    apis: ['ElastiCache:describeCacheClusters'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var deprecatedVersions = {
            '5.0.0' : 'redis',
            '5.0.3' : 'redis',
            '5.0.4' : 'redis',
            '5.0.5' : 'redis',
            '2.6.13': 'redis',
            '2.8.6' : 'redis',
            '2.8.19': 'redis',
        };

        var nonRecommendedVersions = {
            '3.2.4'  : 'redis',
            '2.8.24' : 'redis',
            '2.8.23' : 'redis',
            '2.8.22' : 'redis',
            '2.8.21' : 'redis',
            '2.8.19' : 'redis',
            '2.8.6'  : 'redis',
            '2.6.13' : 'redis',
            '3.2.10' : 'redis',
        };

        async.each(regions.elasticache, function(region, rcb){
            var describeCacheClusters = helpers.addSource(cache, source,
                ['elasticache', 'describeCacheClusters', region]);

            if (!describeCacheClusters) return rcb();

            if (describeCacheClusters.err || !describeCacheClusters.data) {
                helpers.addResult(results, 3,
                    'Unable to query for ElastiCache clusters: ' + helpers.addError(describeCacheClusters), region);
                return rcb();
            }

            if (!describeCacheClusters.data.length) {
                helpers.addResult(results, 0, 'No ElastiCache clusters found', region);
                return rcb();
            }
            
            for (var cluster of describeCacheClusters.data) {
                if (!cluster.ARN || cluster.Engine !== 'redis') continue;

                var resource = cluster.ARN;

                if  (cluster.EngineVersion) {
                    var version = cluster.EngineVersion;
                    let versionDeprecationType = (deprecatedVersions[version]) ? deprecatedVersions[version] : null;
                    let versionSpecifiedType = (nonRecommendedVersions[version]) ? nonRecommendedVersions[version] : null;

                    if (versionDeprecationType) {
                        helpers.addResult(results, 2,
                            'ElastiCache redis cluster is using ' + version + ' engine version which is deprecated',
                            region, resource);
                    } else if (versionSpecifiedType) {
                        helpers.addResult(results, 2,
                            'ElastiCache redis cluster is using ' + version + ' engine version which is not recommended',
                            region, resource);
                    } else {
                        helpers.addResult(results, 0,
                            'ElastiCache redis cluster is using ' + version + ' engine version',
                            region, resource);
                    }
                } else {
                    helpers.addResult(results, 2, 'ElastiCache redis cluster is using unknown engine version', region, resource);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};