var expect = require('chai').expect;
var plugin = require('./adminUserAPIKeys');

const users = [
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
        "email": "test2@aquasec.com",
        "emailVerified": false,
        "identityProviderId": null,
        "externalIdentifier": null,
        "timeModified": "2022-01-09T14:53:08.201Z",
        "isMfaActivated": false,
        "lastSuccessfulLoginTime": "2022-01-09T14:52:08.882Z",
        "id": "ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
        "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
        "name": "test2@aquasec.com",
        "description": "Muhammad admin",
        "timeCreated": "2022-01-04T17:18:33.571Z",
        "freeformTags": {},
        "definedTags": {
            "Oracle-Tags": {
                "CreatedBy": "tomer.daniel@aquasec.com",
                "CreatedOn": "2022-01-04T17:18:33.494Z"
            }
        },
        "lifecycleState": "ACTIVE"
    },
];

const groups = [
    {
        "id": "ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq",
        "compartmentId": "ocid1.tenancy.oc1..aaaaaanemweaxe4b6q2gcodq",
        "name": "Administrators",
        "description": "Administrators",
        "timeCreated": "2022-01-04T16:41:28.470Z",
        "freeformTags": {},
        "definedTags": {},
        "lifecycleState": "ACTIVE"
    }
]

const createCache = (userData, groupData, userErr, groupErr) => {
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
                    data: userData
                }
            }
        },
        group: {
            list: {
                'us-ashburn-1': {
                    err: groupErr,
                    data: groupData
                }
            }
        },
        userGroupMembership: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                          "userId": "ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
                          "groupId": "ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq",
                          "id": "ocid1.groupmembership.oc1..aaaaaaaabis5ze6hqgxd77hn3j7z6vy6m3xtq6ydzo2hc3j6hnod37hsh6fq",
                          "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
                          "description": "GRP_MBR:ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq-ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
                          "timeCreated": "2022-01-04T17:18:39.587Z",
                          "lifecycleState": "ACTIVE"
                        },
                        {
                          "userId": "ocid1.user.oc1..aaadnfbtjs35pen2qr3b3tzqmq",
                          "groupId": "ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq",
                          "id": "ocid1.groupmembership.oc1..aaaaaaaanbleveej3cu2rxfkdqyiidg3mwcz4tm32ug7oyiimnf3y34r2q4a",
                          "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
                          "description": "GRP_MBR:ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq-ocid1.user.oc1..aaadnfbtjs35pen2qr3b3tzqmq",
                          "timeCreated": "2022-01-04T17:00:10.630Z",
                          "lifecycleState": "ACTIVE"
                        },
                        {
                          "userId": "ocid1.user.oc1..aaaaaaaaqii64e6rkq55nm36h37rvvei3wq43nfuyvg5vsnh5t7sftwgyw3q",
                          "groupId": "ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq",
                          "id": "ocid1.groupmembership.oc1..aaaaaaaaeakryb4nlhi2vr3wwxcelgbjsvh66uk55ffdgt2o4zyb57snvneq",
                          "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
                          "description": "GRP_MBR:ocid1.group.oc1..pidxp7gzxcmsfxyow2p6i6siyagvgdysbuk7iq-ocid1.user.oc1..aaaaaaaaqii64e6rkq55nm36h37rvvei3wq43nfuyvg5vsnh5t7sftwgyw3q",
                          "timeCreated": "2022-01-04T16:41:28.470Z",
                          "lifecycleState": "ACTIVE"
                        },
                        {
                          "userId": "ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
                          "groupId": "ocid1.group.oc1..aaaaaaaatf7gxukphgsxjpk7ypge6jd6ilxuwp4pfsvwjzvfloirep42o3kq",
                          "id": "ocid1.groupmembership.oc1..aaaaaaaaqed6hoql3ud5ekesy7kchjqjrrhdcnv7qt3mhgpqrxzaxdaaowva",
                          "compartmentId": "ocid1.tenancy.oc1..aaaaaasyctt3vhme6rnemweaxe4b6q2gcodq",
                          "description": "GRP_MBR:ocid1.group.oc1..aaaaaaaatf7gxukphgsxjpk7ypge6jd6ilxuwp4pfsvwjzvfloirep42o3kq-ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
                          "timeCreated": "2022-01-09T12:42:39.396Z",
                          "lifecycleState": "ACTIVE"
                        }
                    ]
                }
            }
        },
        apiKey: {
            list: {
                'us-ashburn-1': {
                    data: [
                        {
                          "timeCreated": "2022-01-09T12:34:21.976Z",
                          "userId": "ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa",
                          "fingerprint": "65:ab:7d:b9:54:a8:7e:c7:42:cb:5a:87:2f:ed:08:d3",
                          "keyValue": "",
                          "keyId": "ocid1.tenancy.oc1..aaaaa2gcodq/ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa/65:ab:7d:b9:54:a8:7e:c7:42:cb:5a:87:2f:ed:08:d3",
                          "lifecycleState": "ACTIVE",
                          "users": "ocid1.user.oc1..aaaaaaaarekfkxmha6u5cyvqjkmvo7kdxa"
                        }
                    ]
                }
            }
        }
    }
};

describe('adminUserAPIKeys', function () {
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
                undefined,
                {},
                { err: 'no data found' }
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
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result API keys exist for admin user', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.include('API keys exist for admin user')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [users[1]],
                groups
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result API key does not exist for admin user', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('API key does not exist for admin user')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [users[0]],
                groups
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if No groups found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No groups found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [users[1]],
                []
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query user group', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query user group')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                [users[1]],
                null,
                null
            );

            plugin.run(cache, {}, callback);
        });
    });
});