const expect = require('chai').expect;
const iamUserNameRegex = require('./iamUserNameRegex');

const users = [
    {
      "user": "<root_account>",
      "arn": "arn:aws:iam::112233445566:root",
      "user_creation_time": "2020-08-09T16:55:28+00:00",
      "password_enabled": "not_supported",
      "password_last_used": "2020-09-17T21:45:22+00:00",
      "password_last_changed": "not_supported",
      "password_next_rotation": "not_supported",
      "mfa_active": false
    },
    {
      "user": "test1",
      "arn": "arn:aws:iam::112233445566:user/test1",
      "user_creation_time": "2020-09-12T16:58:32+00:00",
      "password_enabled": true,
      "password_last_used": "2020-09-24T10:15:34+00:00",
      "password_last_changed": "2020-09-12T17:02:21+00:00",
      "password_next_rotation": null,
      "mfa_active": false
    },
    {
        "user": "tes11",
        "arn": "arn:aws:iam::112233445566:user/tes11",
        "user_creation_time": "2020-09-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-09-24T10:15:34+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false
      }
];

const createCache = (users) => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    data: users,
                },
            }
        }
    };
};

const createErrorCache = () => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    err: {
                        message: 'error generating credential report'
                    },
                },
            },
        },
    };
};

const createNullCache = () => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': null,
            },
        },
    };
};

describe('iamUserNameRegex', function () {
    describe('run', function () {
        it('should PASS if IAM username matches regex', function (done) {
            const cache = createCache([users[1]]);
            const settings = { iam_username_regex: '^test(.+)' }
            iamUserNameRegex.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if IAM username improperly named', function (done) {
            const cache = createCache([users[2]]);
            const settings = { iam_username_regex: '^test(.+)' }
            iamUserNameRegex.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if IAM username is of Root Account', function (done) {
            const cache = createCache([users[0]]);
            iamUserNameRegex.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for IAM credetial report', function (done) {
            const cache = createErrorCache();
            iamUserNameRegex.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM credential report', function (done) {
            const cache = createNullCache();
            iamUserNameRegex.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
