var expect = require('chai').expect;
const mskClusterUnauthAccess = require('./mskClusterUnauthAccess');

const listClusters = [
    {
        "ClientAuthentication": {
            "Sasl": {
                "Scram": {
                    "Enabled": false
                },
                "Iam": {
                    "Enabled": true
                }
            },
            "Tls": {
                "CertificateAuthorityArnList": [],
                "Enabled": false
            },
            "Unauthenticated": {
                "Enabled": false
            }
        },
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/myCluster/794ab280-627c-4705-aaab-9f5b944fb9e3-25",
        "ClusterName": "myCluster",
        "CreationTime": "2022-04-06T14:16:16.579000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },  
    },
    {
        
        "ClientAuthentication": {
            "Sasl": {
                "Scram": {
                    "Enabled": false
                },
                "Iam": {
                    "Enabled": true
                }
            },
            "Tls": {
                "CertificateAuthorityArnList": [],
                "Enabled": false
            },
            "Unauthenticated": {
                "Enabled": true
            }
        },
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/sadeedcluster/b08122a8-7104-476a-b6ee-c59444fb04d5-25",
        "ClusterName": "sadeedcluster",
        "CreationTime": "2022-04-06T14:19:41.573000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
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

const createNullCache = () => {
    return {
        kafka: {
            listClusters: {
                'us-east-1': null,
            },
        },
    };
};

describe('mskClusterUnauthAccess', function () {
    describe('run', function () {
        it('should FAIL if Unauthentication is enabled for clients, and all actions are allowed', function (done) {
            const cache = createCache([listClusters[1]]);
            mskClusterUnauthAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Cluster has unauthenticated access enabled');
                done();
            });
        });

        it('should PASS if Unauthentication is disabled for clients, and all actions are not allowed', function (done) {
            const cache = createCache([listClusters[0]]);
            mskClusterUnauthAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Cluster does not have unauthenticated access enabled');
                done();
            });
        });

        it('should PASS no MSK clusters found', function (done) {
            const cache = createCache([]);
            mskClusterUnauthAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MSK clusters found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for MSK clusters', function (done) {
            const cache = createErrorCache();
            mskClusterUnauthAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MSK clusters');
                done();
            });
        });

        it('should not return any results if there was an error querying for MSK clusters', function (done) {
            const cache = createNullCache();
            mskClusterUnauthAccess.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
