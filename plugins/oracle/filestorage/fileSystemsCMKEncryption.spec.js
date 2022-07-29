var expect = require('chai').expect;
var plugin = require('./fileSystemsCMKEncryption');

const fileSystems = [
    {
        "compartmentId": 'ocid1.tenancy.oc1.aaaaa.111111',
        "displayName": 'FileSystem1',
        "id": 'ocid1.filesystem.oc1.iad.1111',
        "lifecycleState": 'ACTIVE',
        "timeCreated": '2022-05-29T21:12:16.928Z',
        "kmsKeyId": '',
    },
    {
        "compartmentId": 'ocid1.tenancy.oc1.aaaaa.111111',
        "displayName": 'FileSystem1',
        "id": 'ocid1.filesystem.oc1.iad.1111',
        "lifecycleState": 'ACTIVE',
        "timeCreated": '2022-05-29T21:12:16.928Z',
        "kmsKeyId": 'key-1',
      },
];

const createCache = (err, data) => {
    return {
        regionSubscription: {
            "list": {
                "us-ashburn-1": {
                    "data": [
                        {
                            "regionKey": "IAD",
                            "regionName": "us-ashburn-1",
                            "status": "READY",
                            "isHomeRegion": true
                        },
                        {
                            "regionKey": "LHR",
                            "regionName": "uk-london-1",
                            "status": "READY",
                            "isHomeRegion": false
                        },
                        {
                            "regionKey": "PHX",
                            "regionName": "us-phoenix-1",
                            "status": "READY",
                            "isHomeRegion": false
                        }
                    ]
                }
            }
        },
        fileSystem: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        vault: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "displayName": "vault-1",
                            "freeformTags": {},
                            "id": "vault-1",
                            "lifecycleState": "ACTIVE",
                        },
                    ]
                }
            }
        },
        keys: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                            "compartmentId": "compartment-1",
                            "definedTags": {},
                            "displayName": "key-1",
                            "freeformTags": {},
                            "id": "key-1",
                            "lifecycleState": "ENABLED",
                            "timeCreated": "2022-04-30T19:49:12.841Z",
                            "vaultId": "vault-1",
                            "protectionMode": "SOFTWARE",
                            "algorithm": "AES"
                        }
                    ],
                
                }
            }
        }
    }
};

describe('fileSystemsCMKEncryption', function () {
    describe('run', function () {
        it('should give unknown result if a file system error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for file systems')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no file systems are found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No file systems found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })


        it('should give failing result if file system does not have desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('which is less')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [fileSystems[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if file system has desired encryption level', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('which is greater than or equal to')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [fileSystems[1]]
            );

            plugin.run(cache, {}, callback);
        });
    });
});