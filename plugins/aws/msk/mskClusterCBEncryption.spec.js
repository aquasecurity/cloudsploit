var expect = require('chai').expect;
const mskClusterCBEncryption = require('./mskClusterCBEncryption');

const listClusters = [
    {
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/sadeedcluster/b08122a8-7104-476a-b6ee-c59444fb04d5-25",
        "ClusterName": "sadeedcluster",
        "CreationTime": "2022-04-06T14:19:41.573000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
        "CurrentVersion": "K3R76HOPU0Z2CB",
        "EncryptionInfo": {
            "EncryptionAtRest": {
                "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:000011112222:key/39009d78-b364-4a0b-937f-c89a2c2b473f"
            },
            "EncryptionInTransit": {
                "ClientBroker": "TLS",
                "InCluster": true
            }
        },
    },
    {
        "ClusterArn": "arn:aws:kafka:us-east-1:000011112222:cluster/sadeedcluster/b08122a8-7104-476a-b6ee-c59444fb04d5-25",
        "ClusterName": "sadeedcluster",
        "CreationTime": "2022-04-06T14:19:41.573000+00:00",
        "CurrentBrokerSoftwareInfo": {
            "KafkaVersion": "2.6.2"
        },
        "CurrentVersion": "K3R76HOPU0Z2CB",
        "EncryptionInfo": {
            "EncryptionAtRest": {
                "DataVolumeKMSKeyId": "arn:aws:kms:us-east-1:000011112222:key/39009d78-b364-4a0b-937f-c89a2c2b473f"
            },
            "EncryptionInTransit": {
                "ClientBroker": "TLS_PLAINTEXT",
                "InCluster": true
            }
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


describe('mskClusterCBEncryption', function () {
    describe('run', function () {
        it('should FAIL if Encryption between the client and broker is not only TLS encrypted', function (done) {
            const cache = createCache([listClusters[1]]);
            mskClusterCBEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Encryption between the client and broker is not only TLS encrypted');
                done();
            });
        });

        it('should PASS if Encryption between the client and broker is only TLS encrypted', function (done) {
            const cache = createCache([listClusters[0]]);
            mskClusterCBEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Encryption between the client and broker is only TLS encrypted');
                done();
            });
        });

        it('should PASS if no MSK clusters found', function (done) {
            const cache = createCache([]);
            mskClusterCBEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No MSK clusters found');
                done();
            });
        });

        it('should UNKNOWN if Unable to query for MSK clusters', function (done) {
            const cache = createCache(null);
            mskClusterCBEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MSK clusters');
                done();
            });
        });

        it('should not return any results if there was an error querying for MSK clusters', function (done) {
            const cache = createErrorCache();
            mskClusterCBEncryption.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                done();
            });
        });
    });
});
