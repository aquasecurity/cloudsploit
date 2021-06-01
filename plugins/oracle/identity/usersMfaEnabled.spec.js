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