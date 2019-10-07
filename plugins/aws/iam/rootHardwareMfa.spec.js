var assert = require('assert');
var expect = require('chai').expect;
var rootHardwareMfa = require('./rootHardwareMfa')

const createCache = (enabled, devices) => {
    return {
        iam: {
            getAccountSummary: {
                'us-east-1': {
                    data: {
                        AccountMFAEnabled: enabled
                    }
                }
            },
            listVirtualMFADevices: {
                'us-east-1': {
                    data: devices
                }
            }
        }
    }
}

describe('rootHardwareMfa', function () {
    describe('run', function () {
        it('should FAIL when root account does not have MFA enabled', function (done) {
            const cache = createCache(0, [])

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            rootHardwareMfa.run(cache, {}, callback)
        })

        it('should FAIL when root account has a virtual MFA enabled', function (done) {
            const cache = createCache(1, [
                {
                    "SerialNumber": "arn:aws:iam::012345678910:mfa/root-account-mfa-device",
                    "User": {
                        "UserName": "root",
                        "UserId": "012345678910",
                        "Arn": "arn:aws:iam::012345678910:root",
                        "CreateDate": "2015-04-26T19:45:54.000Z",
                        "PasswordLastUsed": "2019-10-05T00:37:16.000Z",
                        "Tags": []
                    },
                    "EnableDate": "2017-08-23T03:50:37.000Z"
                }
            ])

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(2)
                done()
            }

            rootHardwareMfa.run(cache, {}, callback)
        })

        it('should PASS when root account has a hardware MFA enabled', function (done) {
            const cache = createCache(1, [])

            const callback = (err, results) => {
                expect(results.length).to.equal(1)
                expect(results[0].status).to.equal(0)
                done()
            }

            rootHardwareMfa.run(cache, {}, callback)
        })
    })
})
