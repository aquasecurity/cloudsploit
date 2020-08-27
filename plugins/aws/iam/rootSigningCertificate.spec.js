var expect = require('chai').expect;
const rootSigningCertificate = require('./rootSigningCertificate');

const credentialReports = [
    {
      user: '<root_account>',
      arn: 'arn:aws:iam::111122223333:root',
      user_creation_time: '2020-08-09T16:55:28+00:00',
      password_enabled: 'not_supported',
      password_last_used: '2020-08-17T21:13:44+00:00',
      password_last_changed: 'not_supported',
      password_next_rotation: 'not_supported',
      mfa_active: false,
      access_key_1_active: true,
      access_key_1_last_rotated: '2020-08-17T21:15:23+00:00',
      access_key_1_last_used_date: null,
      access_key_1_last_used_region: null,
      access_key_1_last_used_service: null,
      access_key_2_active: false,
      access_key_2_last_rotated: null,
      access_key_2_last_used_date: null,
      access_key_2_last_used_region: null,
      access_key_2_last_used_service: null,
      cert_1_active: false,
      cert_1_last_rotated: null,
      cert_2_active: false,
      cert_2_last_rotated: null
    },
    {
      user: '<root_account>',
      arn: 'arn:aws:iam::111122223333:user/cloudsploit',
      user_creation_time: '2020-08-17T09:07:27+00:00',
      password_enabled: true,
      password_last_used: 'no_information',
      password_last_changed: '2020-08-17T09:07:29+00:00',
      password_next_rotation: null,
      mfa_active: false,
      access_key_1_active: true,
      access_key_1_last_rotated: '2020-08-17T09:07:29+00:00',
      access_key_1_last_used_date: null,
      access_key_1_last_used_region: null,
      access_key_1_last_used_service: null,
      access_key_2_active: false,
      access_key_2_last_rotated: null,
      access_key_2_last_used_date: null,
      access_key_2_last_used_region: null,
      access_key_2_last_used_service: null,
      cert_1_active: true,
      cert_1_last_rotated: null,
      cert_2_active: false,
      cert_2_last_rotated: null
    },
    {
      user: 'codesploit',
      arn: 'arn:aws:iam::111122223333:user/cloudsploit',
      user_creation_time: '2020-08-17T09:07:27+00:00',
      password_enabled: true,
      password_last_used: 'no_information',
      password_last_changed: '2020-08-17T09:07:29+00:00',
      password_next_rotation: null,
      mfa_active: false,
      access_key_1_active: true,
      access_key_1_last_rotated: '2020-08-17T09:07:29+00:00',
      access_key_1_last_used_date: null,
      access_key_1_last_used_region: null,
      access_key_1_last_used_service: null,
      access_key_2_active: false,
      access_key_2_last_rotated: null,
      access_key_2_last_used_date: null,
      access_key_2_last_used_region: null,
      access_key_2_last_used_service: null,
      cert_1_active: true,
      cert_1_last_rotated: null,
      cert_2_active: false,
      cert_2_last_rotated: null
    }
]

const createCache = (credentialReports) => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    data: credentialReports
                },
            },
        },
    };
};

const createErrorCache = () => {
    return {
        iam: {
            generateCredentialReport: {
                'us-east-1': {
                    err: {
                        message: 'error describing cloudformation stacks'
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

describe('rootSigningCertificate', function () {
    describe('run', function () {

        it('should PASS if the root user is not using x509 singing certificates', function (done) {
            const cache = createCache([credentialReports[0]]);
            rootSigningCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should FAIL if the root user is using x509 singing certificates', function (done) {
            const cache = createCache([credentialReports[1]]);
            rootSigningCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if the root user is not found', function (done) {
            const cache = createCache([credentialReports[2]]);
            rootSigningCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return any results if unable to fetch credential reports', function (done) {
            const cache = createNullCache();
            rootSigningCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

        it('should UNKNOWN if error occurs while fetching credential reports', function (done) {
            const cache = createErrorCache();
            rootSigningCertificate.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });
    });
});