var expect = require('chai').expect;
const accessKeysRotated = require('./accessKeysRotated');

const generateCredentialReport = [
    {
        "user": "<root_account>",
        "arn": "arn:aws:iam::111122223333:root",
        "user_creation_time": "2020-08-09T16:55:28+00:00",
        "password_enabled": "not_supported",
        "password_last_used": "2020-11-11T10:33:09+00:00",
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
        "user": "cloudsploit",
        "arn": "arn:aws:iam::111122223333:user/cloudsploit",
        "user_creation_time": "2020-09-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-11-13T13:18:29+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false,
        "access_key_1_active": true,
        "access_key_1_last_rotated": "2020-09-12T16:58:34+00:00",
        "access_key_1_last_used_date": "2020-10-13T16:14:00+00:00",
        "access_key_1_last_used_region": "us-east-1",
        "access_key_1_last_used_service": "kms",
        "access_key_2_active": true,
        "access_key_2_last_rotated": "2020-10-13T16:14:00+00:00",
        "access_key_2_last_used_date": "2020-10-13T16:14:00+00:00",
        "access_key_2_last_used_region": null,
        "access_key_2_last_used_service": null,
        "cert_1_active": false,
        "cert_1_last_rotated": null,
        "cert_2_active": false,
        "cert_2_last_rotated": null
    },
    {
        "user": "cloudsploit",
        "arn": "arn:aws:iam::111122223333:user/cloudsploit",
        "user_creation_time": "2019-09-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-11-13T13:18:29+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false,
        "access_key_1_active": true,
        "access_key_1_last_rotated": "2020-07-13T16:14:00+00:00",
        "access_key_1_last_used_date": "2020-07-13T16:14:00+00:00",
        "access_key_1_last_used_region": "us-east-1",
        "access_key_1_last_used_service": "kms",
        "access_key_2_active": true,
        "access_key_2_last_rotated": "2020-07-13T16:14:00+00:00",
        "access_key_2_last_used_date": "2020-07-13T16:14:00+00:00",
        "access_key_2_last_used_region": null,
        "access_key_2_last_used_service": null,
        "cert_1_active": false,
        "cert_1_last_rotated": null,
        "cert_2_active": false,
        "cert_2_last_rotated": null
    },
    {
        "user": "cloudsploit",
        "arn": "arn:aws:iam::111122223333:user/cloudsploit",
        "user_creation_time": "2019-09-12T16:58:32+00:00",
        "password_enabled": true,
        "password_last_used": "2020-11-13T13:18:29+00:00",
        "password_last_changed": "2020-09-12T17:02:21+00:00",
        "password_next_rotation": null,
        "mfa_active": false,
        "access_key_1_active": true,
        "access_key_1_last_rotated": "2020-02-12T16:58:34+00:00",
        "access_key_1_last_used_date": "2020-02-13T16:14:00+00:00",
        "access_key_1_last_used_region": "us-east-1",
        "access_key_1_last_used_service": "kms",
        "access_key_2_active": true,
        "access_key_2_last_rotated": "2020-02-13T16:14:00+00:00",
        "access_key_2_last_used_date": "2020-02-13T16:14:00+00:00",
        "access_key_2_last_used_region": null,
        "access_key_2_last_used_service": null,
        "cert_1_active": false,
        "cert_1_last_rotated": null,
        "cert_2_active": false,
        "cert_2_last_rotated": null
    }
];

const createCache = (report) => {
    return {
        iam:{
            generateCredentialReport: {
                'us-east-1': {
                    data: report
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam:{
            generateCredentialReport: {
                'us-east-1': {
                    err: {
                        message: 'error generating credential report'
                    },
                },
            }
        },
    };
};

const createNullCache = () => {
    return {
        iam:{
            generateCredentialReport: {
                'us-east-1': null,
            },
        },
    };
};

describe('accessKeysRotated', function () {
    describe('run', function () {
        it('should PASS if the user access key was last rotated within the pass limit', function (done) {
            const cache = createCache([generateCredentialReport[0],generateCredentialReport[0],generateCredentialReport[1]]);
            var settings = {
                access_keys_last_rotated_fail: 180,
                access_keys_last_rotated_warn: 90
            };
            accessKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(0);
                expect(results[1].status).to.equal(0);
                done();
            });
        });

        it('should WARN if the user access key was last rotated within the warn limit', function (done) {
            const cache = createCache([generateCredentialReport[0],generateCredentialReport[0],generateCredentialReport[2]]);
            var settings = {
                access_keys_last_rotated_fail: 180,
                access_keys_last_rotated_warn: 90
            };
            accessKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(1);
                expect(results[1].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if the user access key was last rotated more than the fail limit', function (done) {
            const cache = createCache([generateCredentialReport[0],generateCredentialReport[0],generateCredentialReport[3]]);
            var settings = {
                access_keys_last_rotated_fail: 180,
                access_keys_last_rotated_warn: 90
            };
            accessKeysRotated.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(2);
                expect(results[0].status).to.equal(2);
                expect(results[1].status).to.equal(2);
                done();
            });
        });

        it('should PASS if no IAM user using access keys found', function (done) {
            const cache = createCache([]);
            accessKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if unable to generate credential report', function (done) {
            const cache = createErrorCache();
            accessKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if generate credential report response not found', function (done) {
            const cache = createNullCache();
            accessKeysRotated.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
