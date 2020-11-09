const expect = require('chai').expect;
const sshKeysRotated = require('./sshKeysRotated');

const users = [
    {
      "user": "<root_account>",
      "arn": "arn:aws:iam::112233445566:root",
      "user_creation_time": "2020-08-09T16:55:28+00:00",
      "password_enabled": "not_supported",
      "password_last_used": "2020-09-17T21:45:22+00:00",
      "password_last_changed": "not_supported",
      "password_next_rotation": "not_supported",
      "mfa_active": false,
      "access_key_1_active": true,
      "access_key_1_last_rotated": "2020-08-18T14:36:56+00:00",
      "access_key_1_last_used_date": "2020-08-18T15:24:00+00:00",
      "access_key_1_last_used_region": "us-east-1",
      "access_key_1_last_used_service": "iam",
      "access_key_2_active": true,
      "access_key_2_last_rotated": "2020-08-23T22:07:52+00:00",
      "access_key_2_last_used_date": "2020-09-06T00:35:00+00:00",
      "access_key_2_last_used_region": "us-east-1",
      "access_key_2_last_used_service": "s3",
      "cert_1_active": false,
      "cert_1_last_rotated": null,
      "cert_2_active": false,
      "cert_2_last_rotated": null
    },
    {
      "user": "test1",
      "arn": "arn:aws:iam::112233445566:user/test1",
      "user_creation_time": "2020-03-12T16:58:32+00:00",
      "password_enabled": true,
      "password_last_used": "2020-09-24T23:53:25+00:00",
      "password_last_changed": "2020-09-12T17:02:21+00:00",
      "password_next_rotation": null,
      "mfa_active": false,
      "access_key_1_active": true,
      "access_key_1_last_rotated": "2020-09-12T16:58:34+00:00",
      "access_key_1_last_used_date": "2020-09-25T02:55:00+00:00",
      "access_key_1_last_used_region": "us-east-1",
      "access_key_1_last_used_service": "autoscaling",
      "access_key_2_active": false,
      "access_key_2_last_rotated": null,
      "access_key_2_last_used_date": null,
      "access_key_2_last_used_region": null,
      "access_key_2_last_used_service": null,
      "cert_1_active": true,
      "cert_1_last_rotated": "2019-10-25T11:08:44+00:00",
      "cert_2_active": false,
      "cert_2_last_rotated": null
    },
    {
        "user": "test2",
        "arn": "arn:aws:iam::112233445566:user/test2",
        "user_creation_time": "2020-09-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-09-24T23:53:25+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false,
        "access_key_1_active": true,
        "access_key_1_last_rotated": "2020-09-12T16:58:34+00:00",
        "access_key_1_last_used_date": "2020-09-25T02:55:00+00:00",
        "access_key_1_last_used_region": "us-east-1",
        "access_key_1_last_used_service": "autoscaling",
        "access_key_2_active": false,
        "access_key_2_last_rotated": null,
        "access_key_2_last_used_date": null,
        "access_key_2_last_used_region": null,
        "access_key_2_last_used_service": null,
        "cert_1_active": true,
        "cert_1_last_rotated": "2020-03-25T11:08:44+00:00",
        "cert_2_active": false,
        "cert_2_last_rotated": null
    },
    {
        "user": "test3",
        "arn": "arn:aws:iam::112233445566:user/test3",
        "user_creation_time": "2020-05-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-09-24T23:53:25+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false,
        "access_key_1_active": true,
        "access_key_1_last_rotated": "2020-09-12T16:58:34+00:00",
        "access_key_1_last_used_date": "2020-09-25T02:55:00+00:00",
        "access_key_1_last_used_region": "us-east-1",
        "access_key_1_last_used_service": "autoscaling",
        "access_key_2_active": false,
        "access_key_2_last_rotated": null,
        "access_key_2_last_used_date": null,
        "access_key_2_last_used_region": null,
        "access_key_2_last_used_service": null,
        "cert_1_active": true,
        "cert_1_last_rotated": "2020-03-25T11:08:44+00:00",
        "cert_2_active": false,
        "cert_2_last_rotated": null
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

describe('sshKeysRotated', function () {
    describe('run', function () {
        it('should PASS if SSH keys has never been rotated but IAM user was created in last 90 days', function (done) {
            const cache = createCache([users[2],users[0]]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if IAM user was created more than 90 days ago and SSH key is older than set number of days', function (done) {
            const cache = createCache([users[0], users[3]]);
            const settings = { ssh_keys_rotated_warn: 150 }
            sshKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if IAM user was created more than 180 days ago and SSH key is older than set number of days', function (done) {
            const cache = createCache([users[0], users[1]]);
            const settings = { ssh_keys_rotated_fail: 300 }
            sshKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no SSH keys found', function (done) {
            const cache = createCache([users[1]]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should PASS if no IAM user accounts with SSh keys found', function (done) {
            const cache = createCache([users[0]]);
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if there was an error querying for IAM credetial report', function (done) {
            const cache = createErrorCache();
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to query for IAM credential report', function (done) {
            const cache = createNullCache();
            sshKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });
    });
});
