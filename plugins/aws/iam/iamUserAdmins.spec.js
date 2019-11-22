var assert = require('assert');
var expect = require('chai').expect;
var iamUserAdmins = require('./iamUserAdmins');

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

describe('iamUserAdmins', function () {
    describe('run', function () {
        it('should FAIL when no users are found', function (done) {
            const settings = {
                iam_admin_count_minimum: 1,
                iam_admin_count_maximum: 8
            }

            const cache = createCache(
                [{}]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(0)
                done()
            }

            iamUserAdmins._run(cache, settings, callback)
        })

        it('should PASS when users are found and fit within range', function (done) {
            const settings = {
                iam_admin_count_minimum: 1,
                iam_admin_count_maximum: 8
            }

            const cache = createCache(
                [{
                    user: '<root_account>'
                }]
            )

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            iamUserAdmins._run(cache, settings, callback)
        })

    
    })
})
