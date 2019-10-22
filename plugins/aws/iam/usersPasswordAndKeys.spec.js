var assert = require('assert');
var expect = require('chai').expect;
var usersPasswordAndKeys = require('./usersPasswordAndKeys')

const createCache = (users) => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    data: users
                }
            }
        }
    }
}

describe('usersPasswordAndKeys', function () {
    describe('run', function () {
        it('should FAIL when user has password and an active access key', function (done) {
            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_enabled: true,
                    access_key_1_active: false
                },
                {
                    user: 'UserAccount',
                    password_enabled: true,
                    access_key_1_active: true
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            usersPasswordAndKeys.run(cache, {}, callback)
        })

        it('should PASS when user has password and does not have an active access key', function (done) {
            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_enabled: true,
                    access_key_1_active: false
                },
                {
                    user: 'UserAccount',
                    password_enabled: true,
                    access_key_1_active: false
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            usersPasswordAndKeys.run(cache, {}, callback)
        })
    })
})
