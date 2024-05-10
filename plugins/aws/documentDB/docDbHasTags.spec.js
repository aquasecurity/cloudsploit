var expect = require('chai').expect;
const docDbHasTags = require('./docDbHasTags');

const describeDBClusters = [
    {
      DbClusterResourceId: 'cluster-TWDPR3PSXGUPMCESNBK6W55SH4',
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
      AssociatedRoles: [],
      ClusterCreateTime: '2021-11-10T10:16:49.359Z',
      EnabledCloudwatchLogsExports: [],
      DeletionProtection: true
    },
    {
      DbClusterResourceId: 'cluster-TWDPR3PSXGUPMCESNBK6W55SH4',
      DBClusterArn: 'arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10',
      AssociatedRoles: [],
      ClusterCreateTime: '2021-11-10T10:16:49.359Z',
      EnabledCloudwatchLogsExports: [],
      DeletionProtection: true
    }
];

const getResources = [
    {
        "ResourceARN": "arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10",
        "Tags": [],
    },
     {
        "ResourceARN": "arn:aws:rds:us-east-1:000011112222:cluster:docdb-2021-11-10-10-16-10",
        "Tags": [{key: 'value'}],
    }
]


const createCache = (describeDBClusters, rgData) => {
    return {
        docdb: {
            describeDBClusters: {
                'us-east-1': {
                    err: null,
                    data: describeDBClusters
                }
            },
        },
        resourcegroupstaggingapi: {
            getResources: {
                'us-east-1':{
                    err: null,
                    data: rgData
                }
            }
        },
    };
};

const createNullCache = () => {
    return {
        docdb: {
            describeDBClusters: {
                'us-east-1': null,
            },
        },
    };
};


describe('docDbHasTags', function () {
    describe('run', function () {
        it('should PASS if DocumentDB Cluster has tags', function (done) {
            const cache = createCache([describeDBClusters[0]], [getResources[1]]);
            docDbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('rds has tags')
                done();
            });
        });

        it('should FAIL if DocumentDB Cluster does not have tags', function (done) {
            const cache = createCache([describeDBClusters[0]], [getResources[0]]);
            docDbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('rds does not have any tags')
                done();
            });
        });

        it('should PASS if no DocumentDB Clusters found', function (done) {
            const cache = createCache([]);
            docDbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('No DocumentDB clusters found')
                done();
            });
        });

        it('should UNKNOWN if unable to query DocumentDB Cluster', function (done) {
            const cache = createCache(null, null);
            docDbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to list DocumentDB clusters: Unable to obtain data')
                done();
            });
        });

        it('should give unknown result if unable to query resource group tagging api', function (done) {
            const cache = createCache([describeDBClusters[0]],null);
            docDbHasTags.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].region).to.equal('us-east-1');
                expect(results[0].message).to.include('Unable to query all resources')
                done();
            });
        });
    });
});
