var expect = require('chai').expect;
var plugin = require('./usersPasswordLastUsed');

var passDate = new Date();
passDate.setMonth(passDate.getMonth() - 2);
var failDate = new Date();
failDate.setMonth(failDate.getMonth() - 7);

const user = [
    {
        "description": "login user",
        "email": "user3@gmail.com",
        "emailVerified": false,
        "isMfaActivated": true,
        "id": "111",
        "timeCreated": failDate,
        "lastSuccessfulLoginTime": failDate,
    },
    {
        "description": "login user",
        "email": "user3@gmail.com",
        "emailVerified": false,
        "isMfaActivated": true,
        "id": "111",
        "timeCreated": failDate,
    },
    {
        "email": "user2@gmail.com",
        "emailVerified": true,
        "name": "user2",
        "description": "user2",
        "timeCreated": passDate,
        "lastSuccessfulLoginTime": passDate,
    },
    {
        "email": "user2@gmail.com",
        "emailVerified": true,
        "name": "user2",
        "description": "user2",
        "timeCreated": passDate,
    },
    {
        "description": "login user",
        "email": "user3@gmail.com",
        "emailVerified": false,
        "isMfaActivated": true,
        "id": "111",
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

describe('usersPasswordLastUsed', function () {
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

        it('should give passing result if no user accounts found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No user accounts found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                []
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if no users with password logins found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('No users with password logins found')
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[4], user[4]]
            );

            plugin.run(cache, {}, callback);
        })

        it('should PASS if the user password was last used within the pass limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[2], user[3]]
            );

            plugin.run(cache, { identity_users_password_last_used_fail: 180 }, callback);
        })

        it('should PASS if the user was created within the pass limit but never used', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[3], user[2]]
            );

            plugin.run(cache, { identity_users_password_last_used_fail: 180 }, callback);
        })

        it('should FAIL if the user password was last used within the fail limit', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[0], user[1]]
            );

            plugin.run(cache, { identity_users_password_last_used_fail: 180 }, callback);
        })

        it('should FAIL if the user was created within the fail limit but never used', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(2)
                expect(results[0].region).to.equal('global')
                done()
            };

            const cache = createCache(
                null,
                [user[1], user[0]]
            );

            plugin.run(cache, { identity_users_password_last_used_fail: 180 }, callback);
        })

    });
});