var assert = require('assert');
var expect = require('chai').expect;
var usersMfaEnabled = require('./usersMfaEnabled')

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

describe('usersMfaEnabled', function () {
    describe('run', function () {
        it('should FAIL when user has password and does not have MFA enabled', function (done) {
            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_enabled: true,
                    mfa_active: false
                },
                {
                    user: 'UserAccount',
                    password_enabled: true,
                    mfa_active: false
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            usersMfaEnabled.run(cache, {}, callback)
        })

        it('should PASS when user has password and does not have MFA enabled', function (done) {
            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_enabled: true,
                    mfa_active: false
                },
                {
                    user: 'UserAccount',
                    password_enabled: true,
                    mfa_active: true
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            usersMfaEnabled.run(cache, {}, callback)
        })
    })
})
