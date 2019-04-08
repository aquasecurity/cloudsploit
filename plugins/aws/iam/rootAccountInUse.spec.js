var assert = require('assert');
var expect = require('chai').expect;
var rootAccountInUse = require('./rootAccountInUse')

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

describe('rootAccountInUse', function () {
    describe('run', function () {
        it('should FAIL when root account recently used', function (done) {
            const settings = {
                root_account_in_use_days: 15
            }

            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_last_used: '2019-03-04T15:31:34+00:00',
                    access_key_1_last_used_date: null,
                    access_key_2_last_used_date: null,
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                expect(results[0].message).to.equal('Root account was last used 1 days ago')
                done()
            }

            rootAccountInUse._run(cache, settings, callback, new Date('2019-03-05T15:31:34+00:00'))
        })

        it('should PASS when root account not recently used', function (done) {
            const settings = {
                root_account_in_use_days: 15
            }

            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_last_used: '2018-03-04T15:31:34+00:00',
                    access_key_1_last_used_date: null,
                    access_key_2_last_used_date: null,
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            rootAccountInUse._run(cache, settings, callback, new Date('2019-03-05T15:31:34+00:00'))
        })

        it('should ignore recently used non-root users', function (done) {
            const settings = {
                root_account_in_use_days: 15
            }

            const cache = createCache(
                [{
                    user: '<root_account>',
                    password_last_used: '2018-03-04T15:31:34+00:00',
                    access_key_1_last_used_date: null,
                    access_key_2_last_used_date: null,
                },
                {
                    user: 'AnotherUser',
                    password_last_used: '2019-03-04T15:31:34+00:00',
                    access_key_1_last_used_date: null,
                    access_key_2_last_used_date: null,
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            rootAccountInUse._run(cache, settings, callback, new Date('2019-03-05T15:31:34+00:00'))
        })
    })
})
