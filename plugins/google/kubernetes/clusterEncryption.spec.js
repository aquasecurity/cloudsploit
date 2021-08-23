var assert = require('assert');
var expect = require('chai').expect;
var plugin = require('./clusterEncryption');

const cryptoKeys = [
    {
        name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2",
        primary: {
            name: "projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-1/cryptoKeyVersions/1",
            state: "DESTROYED",
            createTime: "2021-06-17T08:01:36.739860492Z",
            destroyEventTime: "2021-06-18T11:17:00.798768Z",
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
            generateTime: "2021-06-17T08:01:36.739860492Z",
        },
        purpose: "ENCRYPT_DECRYPT",
        createTime: "2021-06-17T08:01:36.739860492Z",
        nextRotationTime: "2021-09-14T19:00:00Z",
        rotationPeriod: "7776000s",
        versionTemplate: {
            protectionLevel: "SOFTWARE",
            algorithm: "GOOGLE_SYMMETRIC_ENCRYPTION",
        },
    }
];
const clusters = [
    {
        "name": "standard-cluster-2",
        "nodePools": [
            {
                "name": "default-pool",
                "config": {
                },
                "initialNodeCount": 3,
                "locations": [
                    "us-central1-a"
                ],
                "status": "RUNNING"
            }
        ],
        "locations": [
            "us-central1-a"
        ],
        "zone": "us-central1-a",
        "status": "RUNNING",
        "currentNodeCount": 2,
        "location": "us-central1-a"
    }, 
    {
        "name": "standard-cluster-1",
        "databaseEncryption": {
            keyName: 'projects/test-dev-aqua/locations/global/keyRings/test-kr/cryptoKeys/test-key-2',
            state: 'ENCRYPTED'
          },
        "locations": [
            "us-central1-a"
        ],
        "zone": "us-central1-a",
        "status": "RUNNING",
        "currentNodeCount": 2,
        "location": "us-central1-a"
    }
];

const createCache = (clustersList, clusterError, keysList, keysErr) => {
    return {
        clusters: {
            list: {
                'global': {
                    err: clusterError,
                    data: clustersList
                }
            }
        },
        cryptoKeys: {
            list: {
                'global': {
                    err: keysErr,
                    data: keysList
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' }]
                }
            }
        }
    }
};


describe('clusterEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a clusters error is passed or no data is present', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query Kubernetes clusters');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(     
                null,
                ['error'],
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no clusters are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Kubernetes clusters found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache([],null, cryptoKeys, null);

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if cluster application-layer secrets encryption level is equal to or greater than desired level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('which is greater than or equal to');
                expect(results[0].region).to.equal('global');
                done()
            };
            const cache = createCache([clusters[1]], null, cryptoKeys, null);
            plugin.run(cache, {}, callback);
        });

        it('should give failing result if cluster application-layer secrets encryption level is less than desired level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache([clusters[0]], null, cryptoKeys, null);

            plugin.run(cache, {}, callback);
        })
        it('should give failing result if cluster application-layer secrets encryption level key is not found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('which is less than');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache([clusters[0]], null, [], null);

            plugin.run(cache, {}, callback);
        })
    })
})