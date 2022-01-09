var expect = require('chai').expect;
var plugin = require('./userAPIKeysRotated');

const apiKeys = [
    {
        "timeCreated": new Date(),
        "userId": "ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa",
        "keyValue": "",
        "keyId": "ocid1.tenancy.oc1..aaaaaaaaip36ginmudtormvwsv45imsyctt3vhme6rnemweaxe4b6q2gcodq/ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa/65:ab:7d:b9:54:a8:7e:c7:42:cb:5a:87:2f:ed:08:d3",
        "lifecycleState": "ACTIVE",
        "users": "ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa"
    },
    {
        "timeCreated": "2021-01-09T12:34:21.976Z",
        "userId": "ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa",
        "keyValue": "",
        "keyId": "ocid1.tenancy.oc1..aaaaaaaaip36ginmudtormvwsv45imsyctt3vhme6rnemweaxe4b6q2gcodq/ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa/65:ab:7d:b9:54:a8:7e:c7:42:cb:5a:87:2f:ed:08:d3",
        "lifecycleState": "ACTIVE",
        "users": "ocid1.user.oc1..aaaaaaaaddzcrvo7kdxa"
    }
];

const createCache = (apiData, userErr, apiErr) => {
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
        user: {
            list: {
                'us-ashburn-1': {
                    err: userErr,
                    data: [
                        {
                            "capabilities": {
                                "canUseConsolePassword": true,
                                "canUseApiKeys": true,
                                "canUseAuthTokens": true,
                                "canUseSmtpCredentials": true,
                                "canUseCustomerSecretKeys": true,
                                "canUseOAuth2ClientCredentials": true,
                                "canUseDbCredentials": true
                            },
                            "email": "test1@aquasec.com",
                            "emailVerified": false,
                            "identityProviderId": null,
                            "externalIdentifier": null,
                            "timeModified": "2022-01-04T17:00:10.630Z",
                            "isMfaActivated": false,
                            "id": "ocid1.user.oc1..aaadnfbtjs35pen2qr3b3tzqmq",
                            "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
                            "name": "test1@aquasec.com",
                            "description": "admin",
                            "timeCreated": "2022-01-04T16:59:57.900Z",
                            "freeformTags": {},
                            "definedTags": {
                                "Oracle-Tags": {
                                    "CreatedBy": "tomer.daniel@aquasec.com",
                                    "CreatedOn": "2022-01-04T16:59:57.803Z"
                                }
                            },
                            "lifecycleState": "ACTIVE"
                        },
                    ]
                }
            }
        }, 
        apiKey: {
            list: {
                'us-ashburn-1': {
                    data: apiData,
                    err: apiErr
                }
            }
        }
    }
};

describe('userAPIKeysRotated', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for users', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for user')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [],
                { error: 'error' }
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result API keys has not been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('API key is')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [apiKeys[1]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result API keys has been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('API key is 0 days old')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [apiKeys[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if No user API keys found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No user API keys found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query user API keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query user API keys')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                null,
                { err: 'err' }
            );

            plugin.run(cache, {}, callback);
        });
    });
});