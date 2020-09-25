var expect = require('chai').expect;
const daxClusterEncryption = require('./daxClusterEncryption');

const clusters = [
    {
        ClusterName: 'test-60',
        ClusterArn: 'arn:aws:dax:us-east-1:123456654321:cache/test-60',
        TotalNodes: 1,
        ActiveNodes: 0,
        NodeType: 'dax.t2.small',
        Status: 'creating',
        ClusterDiscoveryEndpoint: { Port: 8111 },
        PreferredMaintenanceWindow: 'tue:08:30-tue:09:30',
        SubnetGroup: 'test-subnet-dax',
        SecurityGroups: [ { SecurityGroupIdentifier: 'sg-aa941691', Status: 'active' } ],
        IamRoleArn: 'arn:aws:iam::123456654321:role/service-role/DAXtoDynamoDB',
        ParameterGroup: {
          ParameterGroupName: 'default.dax1.0',
          ParameterApplyStatus: 'in-sync',
          NodeIdsToReboot: []
        },
        SSEDescription: { Status: 'ENABLED' }
    },
    {
        ClusterName: 'test1-60',
        ClusterArn: 'arn:aws:dax:us-east-1:123456654321:cache/test1-60',
        TotalNodes: 1,
        ActiveNodes: 0,
        NodeType: 'dax.t2.small',
        Status: 'creating',
        ClusterDiscoveryEndpoint: { Port: 8111 },
        PreferredMaintenanceWindow: 'thu:04:00-thu:05:00',
        SubnetGroup: 'test-subnet-dax',
        SecurityGroups: [ { SecurityGroupIdentifier: 'sg-aa941691', Status: 'active' } ],
        IamRoleArn: 'arn:aws:iam::123456654321:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX',
        ParameterGroup: {
          ParameterGroupName: 'default.dax1.0',
          ParameterApplyStatus: 'in-sync',
          NodeIdsToReboot: []
        },
        SSEDescription: { Status: 'DISABLED' }
    }
];

const createCache = (clusters) => {
    return {
        dax: {
            describeClusters: {
                'us-east-1': {
                    data: clusters,
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        dax: {
            describeClusters: {
                'us-east-1': {
                    err: {
                        message: 'error describing clusters'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        dax: {
            describeClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('daxClusterEncryption', function () {
    describe('run', function () {
        it('should FAIL if encryption is not enabled for DAX cluster', function (done) {
            const cache = createCache([clusters[1]]);
            daxClusterEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if encryption is enabled for DAX cluster', function (done) {
            const cache = createCache([clusters[0]]);
            daxClusterEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no DAX clusters found', function (done) {
            const cache = createCache([]);
            daxClusterEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for DAX clusters', function (done) {
            const cache = createErrorCache();
            daxClusterEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for DAX clusters', function (done) {
            const cache = createNullCache();
            daxClusterEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
