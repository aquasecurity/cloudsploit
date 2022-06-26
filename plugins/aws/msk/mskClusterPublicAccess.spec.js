var expect = require('chai').expect;
const mskClusterPublicAccess = require('./mskClusterPublicAccess');

const listClusters = [
    {
        "BrokerNodeGroupInfo": {
            "BrokerAZDistribution": "DEFAULT",
            "ClientSubnets": [
                "subnet-02ed4181800d4658b",
                "subnet-04464dfb7e3dfe1ff",
                "subnet-04604cc007728c2a7"
            ],
            "InstanceType": "kafka.m5.large",
            "SecurityGroups": [
                "sg-0cb6c99daaa6b73c5"
            ],
            "StorageInfo": {
                "EbsStorageInfo": {
                    "ProvisionedThroughput": {
                        "Enabled": false
                    },
                    "VolumeSize": 1
                }
            },
            "ConnectivityInfo": {
                "PublicAccess": {
                    "Type": "SERVICE_PROVIDED_EIPS"
                }
            }
        },
       
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/myCluster/794ab280-627c-4705-aaab-9f5b944fb9e3-25",
        "ClusterName": "myCluster"
    },
    {
        "BrokerNodeGroupInfo": {
            "BrokerAZDistribution": "DEFAULT",
            "ClientSubnets": [
                "subnet-02ed4181800d4658b",
                "subnet-04464dfb7e3dfe1ff",
                "subnet-06629b4200870c740"
            ],
            "InstanceType": "kafka.m5.large",
            "SecurityGroups": [
                "sg-0cb6c99daaa6b73c5"
            ],
            "StorageInfo": {
                "EbsStorageInfo": {
                    "ProvisionedThroughput": {
                        "Enabled": false
                    },
                    "VolumeSize": 1000
                }
            },
            "ConnectivityInfo": {
                "PublicAccess": {
                    "Type": "DISABLED"
                }
            }
        },
       
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/sadeedcluster/b08122a8-7104-476a-b6ee-c59444fb04d5-25",
        "ClusterName": "sadeedcluster"
        
    }
];

const createCache = (clusters) => {
    return {
        kafka: {
            listClusters: {
                'us-east-1': {
                    data: clusters,
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        kafka: {
            listClusters: {
                'us-east-1': {
                    err: {
                        message: 'error listing clusters'
                    },
                },
            },
        },
    };
};


describe('mskClusterPublicAccess', function () {
    describe('run', function () {
        it('should FAIL if MSK cluster has public access enabled', function (done) {
            const cache = createCache([listClusters[0]]);
            mskClusterPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MSK cluster is publicly accessible');
                done();
            });
        });

        it('should PASS if MSK cluster does not have public access enabled', function (done) {
            const cache = createCache([listClusters[1]]);
            mskClusterPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MSK cluster is not publicly accessible');
                done();
            });
        });

        it('should PASS no MSK clusters found', function (done) {
            const cache = createCache([]);
            mskClusterPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MSK clusters found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for MSK clusters', function (done) {
            const cache = createCache(null);
            mskClusterPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MSK clusters');
                done();
            });
        });

        it('should not return any results if there was an error querying for MSK clusters', function (done) {
            const cache = createErrorCache();
            mskClusterPublicAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                done();
            });
        });
    });
});