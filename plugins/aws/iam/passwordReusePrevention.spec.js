var expect = require('chai').expect;
const passwordReusePrevention = require('./passwordReusePrevention');

const getAccountPasswordPolicy = [
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 90,
        "PasswordReusePrevention": 36
    },
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 210,
        "PasswordReusePrevention": 10
    },
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 400,
        "PasswordReusePrevention": 3
    }
];

const createCache = (report) => {
    return {
        iam:{
            getAccountPasswordPolicy: {
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
            getAccountPasswordPolicy: {
                'us-east-1': {
                    err: {
                        message: 'error generating credential report'
                    },
                },
            }
        },
    };
};

const createErrorCodeCache = () => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': {
                    err: {
                        code: 'NoSuchEntity',
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
            getAccountPasswordPolicy: {
                'us-east-1': null,
            },
        },
    };
};

describe('passwordReusePrevention', function () {
    describe('run', function () {
        it('should PASS if maximum password reuse is suitable', function (done) {
            const cache = createCache(getAccountPasswordPolicy[0]);
            var settings = {
                password_reuse_fail: 5,
                password_reuse_warn: 24
            };
            passwordReusePrevention.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if maximum password reuse is less than warn limit', function (done) {
            const cache = createCache(getAccountPasswordPolicy[1]);
            var settings = {
                password_reuse_fail: 5,
                password_reuse_warn: 24
            };
            passwordReusePrevention.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if maximum password reuse is less than fail limit', function (done) {
            const cache = createCache(getAccountPasswordPolicy[2]);
            var settings = {
                password_reuse_fail: 5,
                password_reuse_warn: 24
            };
            passwordReusePrevention.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if password policy does not prevent reusing previous passwords', function (done) {
            const cache = createCache([]);
            passwordReusePrevention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if account does not have a password policy', function (done) {
            const cache = createErrorCodeCache();
            passwordReusePrevention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get account password policy', function (done) {
            const cache = createErrorCache();
            passwordReusePrevention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get account password policy response not found', function (done) {
            const cache = createNullCache();
            passwordReusePrevention.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
