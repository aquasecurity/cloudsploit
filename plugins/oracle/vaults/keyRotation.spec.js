var expect = require('chai').expect;
var plugin = require('./keyRotation');

var passDate = new Date();
passDate.setMonth(passDate.getMonth() - 1);
var failDate = new Date();
failDate.setYear(failDate.getYear() - 1);

const keys = [
    {
        "compartmentId": "ocid1.tenancy.oc1..aaaa111111",
        "currentKeyVersion": "ocid1.keyversion.oc1.iad.bbbbbbbb.version1",
        "definedTags": {},
        "displayName": "key1",
        "freeformTags": {},
        "id": "ocid1.key.oc1.iad.bbbbbbbb.key1",
        "protectionMode": "HSM",
        "lifecycleState": "ENABLED",
        "timeCreated": failDate,
      },
      {
        "compartmentId": "ocid1.tenancy.oc1..aaaa111111",
        "currentKeyVersion": "ocid1.keyversion.oc1.iad.bbbbbbb.version2",
        "definedTags": {},
        "displayName": "key-1",
        "freeformTags": {},
        "id": "ocid1.key.oc1.iad.bbbbbbb.key2",
        "protectionMode": "SOFTWARE",
        "lifecycleState": "ENABLED",
        "timeCreated": failDate
      }
];

const keyVersions = [
    {
        "compartmentId": 'ocid1.tenancy.oc1..aaaa111111',
        "id": 'ocid1.keyversion.oc1.iad.bbbbbbb.awemmjwzfoaaa.abuwcljrc4nsujs33cxy6o7bf5hcjtq5fce7cqk56o3bcxh4pwkobfbkhpba',
        "keyId": 'ocid1.key.oc1.iad.bbbbbbb.key2',
        "lifecycleState": 'ENABLED',
        "origin": 'INTERNAL',
        "timeCreated": failDate,
        "timeOfDeletion": null,
        "vaultId": 'ocid1.vault.oc1.iad.bbbbbbb.vault1',
        "keys": 'ocid1.key.oc1.iad.bbbbbbb.key2'
    },
    {
        "compartmentId": 'ocid1.tenancy.oc1..aaaa111111',
        "id": 'ocid1.keyversion.oc1.iad.bbbbbbb.version2',
        "keyId": 'ocid1.key.oc1.iad.bbbbbbb.key2',
        "lifecycleState": 'ENABLED',
        "origin": 'INTERNAL',
        "timeCreated": passDate,
        "timeOfDeletion": null,
        "vaultId": 'ocid1.vault.oc1.iad.bbbbbbb.vault1',
        "keys": 'ocid1.key.oc1.iad.bbbbbbb.key2'
      },
      {
          "compartmentId": 'ocid1.tenancy.oc1..aaaa111111',
          "id": 'ocid1.keyversion.oc1.iad.bbbbbbb.awemmjwzfoaaa.abuwcljrc4nsujs33cxy6o7bf5hcjtq5fce7cqk56o3bcxh4pwkobfbkhpba',
          "keyId": 'ocid1.key.oc1.iad.bbbbbbbb.key1',
          "lifecycleState": 'ENABLED',
          "origin": 'INTERNAL',
          "timeCreated": failDate,
          "timeOfDeletion": null,
          "vaultId": 'ocid1.vault.oc1.iad.bbbbbbb.vault1',
          "keys": 'ocid1.key.oc1.iad.bbbbbbb.key2'
      }
]

const createCache = (err, data, versionErr, versionData) => {
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
        keys: {
            get: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        },
        keyVersions: {
            list: {
                'us-ashburn-1': {
                    err: versionErr,
                    data: versionData
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
        }
    }
};

describe('keyRotation', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for cryptographic keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for cryptographic keys')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                ['error'],
                undefined

            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no cryptographic keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No cryptographic keys found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give unknown result if unable to query for cryptographic key versions', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for cryptographic key versions')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                keys,
                ['error'],
                undefined

            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no key versions found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No key versions found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                keys,
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if cryptographic key has not been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('which is greater than')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [keys[0]],
                null,
                keyVersions
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if cryptographic key has been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('which is equal to or less than')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                [keys[1]],
                null,
                keyVersions
            );

            plugin.run(cache, {}, callback);
        });
    });
});