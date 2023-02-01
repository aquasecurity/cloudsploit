var expect = require('chai').expect;
var iamUserNotInUse = require('./iamUserNotInUse')


const dayOldDate = new Date();
dayOldDate.setDate(dayOldDate.getDate()-1);
const oldDate = new Date();
oldDate.setFullYear(oldDate.getFullYear()-1);

const users = [
    {
        "user": "<root_account>",
        "arn": "arn:aws:iam::11111111111:root",
        "password_last_used": oldDate,
        "access_key_1_last_used_date": null,
        "access_key_2_last_used_date": null,
    },
    {
        "user": "kms_key_recovery",
        "arn": "arn:aws:iam::11111111111:user/kms_key_recovery",
        "password_last_used": oldDate,
        "access_key_1_last_used_date": null,
        "access_key_2_last_used_date": null,
    },
    {
        "user": "kms_key_recovery",
        "arn": "arn:aws:iam::11111111111:user/kms_key_recovery",
        "password_last_used": oldDate,
        "access_key_1_last_used_date": dayOldDate,
        "access_key_2_last_used_date": null,
    }
]

const createCache = (users, err = null) => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    data: users,
                    err
                }
            }
        }
    }
}

describe('iamUserNotInUse', function () {
    describe('run', function () {

        it('should give unknown when unable to query for IAM Users', function (done) {
            const settings = {
                iam_user_account_in_use_days: '15'
            };

            const cache = createCache(null, ['error']);
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query IAM users');
                done();
            };

            iamUserNotInUse.run(cache, settings, callback);
        })

        it('should pass when no IAM Users found', function (done) {
            const settings = {
                iam_user_account_in_use_days: '15'
            };

            const cache = createCache([]);
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('No IAM users found');
                done();
            };

            iamUserNotInUse.run(cache, settings, callback);
        })

        it('should pass if IAM user account was recently used', function (done) {
            const settings = {
                iam_user_account_in_use_days: '15'
            };

            const cache = createCache([users[2]]);
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.equal('IAM user was last used 1 days ago');
                done();
            };

            iamUserNotInUse.run(cache, settings, callback);
        })

        it('should PASS if IAM user account was not recently used', function (done) {
            const settings = {
                iam_user_account_in_use_days: '15'
            };

            const cache = createCache([users[1]]);

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            };

            iamUserNotInUse.run(cache, settings, callback);
        })

        it('should ignore root user', function (done) {
            const settings = {
                iam_user_account_in_use_days: '15'
            }

            const cache = createCache([users[0], users[1]]);

            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            };

            iamUserNotInUse.run(cache, settings, callback);
        })
    })
})
