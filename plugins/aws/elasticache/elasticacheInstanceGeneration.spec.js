var expect = require('chai').expect;
const elasticacheInstanceGeneration = require('./elasticacheInstanceGeneration');

const clusters = [
    {
        CacheClusterId: 'test-001',
        ClientDownloadLandingPage: 'https://console.aws.amazon.com/elasticache/home#client-download:',
        CacheNodeType: 'cache.t2.micro',
        Engine: 'redis',
        EngineVersion: '6.0.5',
        CacheClusterStatus: 'available',
        NumCacheNodes: 1,
        PreferredAvailabilityZone: 'us-east-1f',
        CacheClusterCreateTime: '2021-11-10T12:16:41.340Z',
        PreferredMaintenanceWindow: 'mon:09:30-mon:10:30',
        PendingModifiedValues: {},
        CacheSecurityGroups: [],
        CacheParameterGroup: [Object],
        CacheSubnetGroupName: 'elasticache-subnet',
        CacheNodes: [],
        AutoMinorVersionUpgrade: true,
        SecurityGroups: [Array],
        ReplicationGroupId: 'akhtar-ec',
        SnapshotRetentionLimit: 1,
        SnapshotWindow: '03:30-04:30',
        AuthTokenEnabled: false,
        TransitEncryptionEnabled: true,
        AtRestEncryptionEnabled: true,
        ARN: 'arn:aws:elasticache:us-east-1:000111222333:cluster:test-001',
        ReplicationGroupLogDeliveryEnabled: false,
        LogDeliveryConfigurations: []
      },
      {
        CacheClusterId: 'test1-001',
        ClientDownloadLandingPage: 'https://console.aws.amazon.com/elasticache/home#client-download:',
        CacheNodeType: 'cache.m2.4xlarge',
        Engine: 'redis',
        EngineVersion: '6.0.5',
        CacheClusterStatus: 'available',
        NumCacheNodes: 1,
        PreferredAvailabilityZone: 'us-east-1f',
        CacheClusterCreateTime: '2021-11-10T12:17:36.297Z',
        PreferredMaintenanceWindow: 'sat:05:30-sat:06:30',
        PendingModifiedValues: {},
        CacheSecurityGroups: [],
        CacheParameterGroup: [Object],
        CacheSubnetGroupName: 'elasticache-subnet',
        CacheNodes: [],
        AutoMinorVersionUpgrade: true,
        SecurityGroups: [Array],
        ReplicationGroupId: 'akhtar-ec1',
        SnapshotRetentionLimit: 1,
        SnapshotWindow: '04:30-05:30',
        AuthTokenEnabled: false,
        TransitEncryptionEnabled: false,
        AtRestEncryptionEnabled: false,
        ARN: 'arn:aws:elasticache:us-east-1:000111222333:cluster:test1-001',
        ReplicationGroupLogDeliveryEnabled: false,
        LogDeliveryConfigurations: []
      }
];

const createCache = (clusters, err) => {
    return {
        elasticache: {
            describeCacheClusters: {
                'us-east-1': {
                    data: clusters,
                    err: err
                },
            },
        },
    };
};


describe('elasticacheInstanceGeneration', function () {
    describe('run', function () {
        it('should FAIL if ElastiCache cluster is running previous generation', function (done) {
            const cache = createCache([clusters[1]]);
            elasticacheInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if ElastiCache cluster is running current generation', function (done) {
            const cache = createCache([clusters[0]]);
            elasticacheInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no ElastiCache clusters found', function (done) {
            const cache = createCache([]);
            elasticacheInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to query ElastiCache clusters', function (done) {
            const cache = createCache(null, { message: 'Unable to obtain data' });
            elasticacheInstanceGeneration.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});
