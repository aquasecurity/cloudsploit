var expect = require('chai').expect;
var plugin = require('./userAuthTokenRotated');

const authTokens = [
    {
        "id": "ocid1.credential.oc1..aaaaaaaa4f57ig72lh5gu6hicy5d5nl7wzb6q",
        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaip3imsyctt3vhme6rnemweaxe4b6q2gcodq",
        "description": "For CIS",
        "timeCreated": new Date(),
        "userId": "ocid1.user.oc1..aaaaaaaaddzaosqxqgeryy43emaptcnzzcrekfkxmha6u5cyvqjkmvo7kdxa",
        "lifecycleState": "ACTIVE",
        "users": "ocid1.user.oc1..aaaaaaaaddzaosqxqgeryy43emaptcnzzcrekfkxmha6u5cyvqjkmvo7kdxa"
    },
    {
        "id": "ocid1.credential.oc1..aaaaaaaa4f57ig72lh5gu6hicy5d5nl7wzb6q",
        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaip3imsyctt3vhme6rnemweaxe4b6q2gcodq",
        "description": "For CIS",
        "timeCreated": "2021-01-09T14:53:08.201Z",
        "userId": "ocid1.user.oc1..aaaaaaaaddzaosqrekfkxmha6u5cyvqjkmvo7kdxa",
        "lifecycleState": "ACTIVE",
        "users": "ocid1.user.oc1..aaaaaaaaddzaosqrekfkxmha6u5cyvqjkmvo7kdxa"
    }
];

const createCache = (authData, userErr, authErr) => {
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
        authToken: {
            list: {
                'us-ashburn-1': {
                    data: authData,
                    err: authErr
                }
            }
        }
    }
};

describe('userAuthTokenRotated', function () {
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

        it('should give failing result Auth token has not been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('Auth token is')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [authTokens[1]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result Auth token has been rotated within set days limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('Auth token is 0 days old')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [authTokens[0]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if No user auth tokens found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No user auth tokens found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query user auth tokens', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query user auth tokens')
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