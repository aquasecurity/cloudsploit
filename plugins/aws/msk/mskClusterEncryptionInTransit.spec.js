var expect = require('chai').expect;
const mskClusterEncryptionInTransit = require('./mskClusterEncryptionInTransit');

const listClusters = [
    {
        "ClusterArn": "arn:aws:kafka:us-east-1:000111222333:cluster/sad/3dce8c4f-76a7-4b74-b1ec-192dec1a750b-20",
        "ClusterName": "test",
        "CreationTime": "2021-12-01T14:10:20.502000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
        "CurrentVersion": "KTVPDKIKX0DER",
        "EncryptionInfo": {
            "EncryptionAtRest": {
                "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:000111222333:key/39009d78-b364-4a0b-937f-c89a2c2b473f"
            },
            "EncryptionInTransit": {
                "ClientBroker": "TLS_PLAINTEXT",
                "InCluster": true
            }
        },
        "EnhancedMonitoring": "DEFAULT",
    },
    {
        "ClusterArn": "arn:aws:kafka:us-east-1:000111222333:cluster/sadeed/d54ff036-fbce-4272-a3f2-3b50ecb66d57-20",            "ClusterName": "sadeed",
        "ClusterName": "test1",
        "CreationTime": "2021-12-01T14:03:48.709000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
        "CurrentVersion": "K1F83G8C2ARO7P",
        "EncryptionInfo": {
            "EncryptionAtRest": {
                "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:000111222333:key/39009d78-b364-4a0b-937f-c89a2c2b473f"
            },
            "EncryptionInTransit": {
                "ClientBroker": "PLAINTEXT",
                "InCluster": false
            }
        },
        "EnhancedMonitoring": "DEFAULT",
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

describe('mskClusterEncryptionInTransit', function () {
    describe('run', function () {
        it('should FAIL if TLS encryption within the cluster is not enabled', function (done) {
            const cache = createCache([listClusters[1]]);
            mskClusterEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if TLS encryption within the cluster is enabled', function (done) {
            const cache = createCache([listClusters[0]]);
            mskClusterEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS no MSK clusters found', function (done) {
            const cache = createCache([]);
            mskClusterEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for MSK clusters', function (done) {
            const cache = createErrorCache();
            mskClusterEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for MSK clusters', function (done) {
            const cache = createNullCache();
            mskClusterEncryptionInTransit.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
