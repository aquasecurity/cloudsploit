var expect = require('chai').expect;
var plugin = require('./usersMfaEnabled');

const user = [
    {
        "description": "login user",
        "email": "user3@gmail.com",
        "emailVerified": false,
        "isMfaActivated": true,
        "id": "111"
    },
    {
        "defined-tags": {},
        "description": "login user",
        "email": "user1@gmail.com",
        "isMfaActivated": false,
        "id": "111"
    },
    {
        "capabilities": {
          "canUseConsolePassword": false,
          "canUseApiKeys": true,
          "canUseAuthTokens": true,
          "canUseSmtpCredentials": true,
          "canUseCustomerSecretKeys": true,
          "canUseOAuth2ClientCredentials": true,
          "canUseDbCredentials": true
        },
        "emailVerified": true,
        "identityProviderId": "ocid1.saml2idp.oc1..aaaaaaaaknersalsctbatwefdwefdwdxwvnyxpdzlbs4vuuu7zxgjxqts6a",
        "externalIdentifier": "3ec8cd96d83c49aebfc0fccaf8e92d03",
        "timeModified": "2021-12-26T10:48:01.848Z",
        "isMfaActivated": false,
        "id": "ocid1.user.oc1..aaaaaaaayqmr4afeyuihjclv22j6265xacwedwefwfasdwedeqdifoq",
        "compartmentId": "ocid1.tenancy.oc1..aaaaaaaaidksdowchziencs3c3zx4gmpw3weung65id5bdjyw24nbdqih4ya",
        "name": "oracleidentitycloudservice/test@gmail.com",
        "description": "test@gmail.com",
        "timeCreated": "2021-12-26T10:48:00.940Z",
        "freeformTags": {},
        "definedTags": {
          "Oracle-Tags": {
            "CreatedBy": "scim-service",
            "CreatedOn": "2021-12-26T10:48:00.914Z"
          }
        },
        "lifecycleState": "ACTIVE"
    }
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
        user: {
            list: {
                'us-ashburn-1': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('usersMfaEnabled', function () {
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
                {err: 'error'},
                undefined
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if No user accounts found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No user accounts found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[1]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if user has MFA disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(2)
                expect(results[1].message).to.include('The user has MFA disabled')
                expect(results[1].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                user
            );

            plugin.run(cache, {}, callback);
        })
        
        it('should give warning result if federated user has MFA disabled and warn_federated_users setting is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[2].status).to.equal(1)
                expect(results[2].message).to.include('The federated user has MFA disabled')
                expect(results[2].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                user
            );

            plugin.run(cache, { warn_federated_users: 'true' }, callback);
        })

        it('should give passing result if user has MFA enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('The user has MFA enabled')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                user
            );

            plugin.run(cache, {}, callback);
        });
    });
});