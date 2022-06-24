var expect = require('chai').expect;
var plugin = require('./usersEmailVerified');

const user = [
    {
        "description": "login user",
        "email": "user1@gmail.com",
        "emailVerified": true,
        "external-identifier": null,
        "freeform-tags": {},
        "identity-provider-id": null,
        "inactive-status": null,
        "is-mfa-activated": false,
        "last-successful-login-time": "2021-02-22T17:20:19.791000+00:00",
        "lifecycle-state": "ACTIVE",
        "name": "user1",
        "id": "111",
        "previous-successful-login-time": null,
        "time-created": "2021-02-16T18:05:07.150000+00:00"
    },
    {
        "description": "login user",
        "email": "user3@gmail.com",
        "emailVerified": false,
        "external-identifier": null,
        "freeform-tags": {},
        "identity-provider-id": null,
        "inactive-status": null,
        "is-mfa-activated": false,
        "id": "111",
        "last-successful-login-time": "2021-02-22T17:20:19.791000+00:00",
        "lifecycle-state": "ACTIVE",
        "name": "user3",
        "previous-successful-login-time": null,
        "time-created": "2021-02-16T18:05:07.150000+00:00"
    },
    {
        "defined-tags": {},
        "description": "login user",
        "email": "",
        "external-identifier": null,
        "freeform-tags": {},
        "identity-provider-id": null,
        "inactive-status": null,
        "is-mfa-activated": false,
        "last-successful-login-time": "2021-02-25T15:53:51.093000+00:00",
        "lifecycle-state": "ACTIVE",
        "id": "111",
        "name": "user2",
        "previous-successful-login-time": null,
        "time-created": "2021-02-16T17:55:53.412000+00:00"
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

describe('usersEmailVerified', function () {
    describe('run', function () {
        it('should give unknown result if unable to query for users', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(3)
                expect(results[0].message).to.include('Unable to query for users')
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

        it('should give failing result if user does not have an email', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[2].status).to.equal(2)
                expect(results[2].message).to.include('not found')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                user
            );

            plugin.run(cache, {}, callback);
        })

        it('should give failing result if user email is not verified', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[1].status).to.equal(2)
                expect(results[1].message).to.include('not verified')
                expect(results[0].region).to.equal('us-ashburn-1')
                done()
            };

            const cache = createCache(
                null,
                user
            );

            plugin.run(cache, {}, callback);
        })

        it('should give passing result if user email is verified', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0)
                expect(results[0].status).to.equal(0)
                expect(results[0].message).to.include('is verified')
                expect(results[0].region).to.equal('us-ashburn-1')
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