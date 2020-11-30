var expect = require('chai').expect;
const maxPasswordAge = require('./maxPasswordAge');

const getAccountPasswordPolicy = [
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 90
    },
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 210
    },
    {
        "MinimumPasswordLength": 8,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 400
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

describe('maxPasswordAge', function () {
    describe('run', function () {
        it('should PASS if maximum age of password is suitable', function (done) {
            const cache = createCache(getAccountPasswordPolicy[0]);
            var settings = {
                max_password_age_fail: 365,
                max_password_age_warn: 180
            };
            maxPasswordAge.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if maximum age of password is more than six months', function (done) {
            const cache = createCache(getAccountPasswordPolicy[1]);
            var settings = {
                max_password_age_fail: 365,
                max_password_age_warn: 180
            };
            maxPasswordAge.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if maximum age of password is more than one year', function (done) {
            const cache = createCache(getAccountPasswordPolicy[2]);
            var settings = {
                max_password_age_fail: 365,
                max_password_age_warn: 180
            };
            maxPasswordAge.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if password policy does not specify a maximum password age', function (done) {
            const cache = createCache([]);
            maxPasswordAge.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if account does not have a password policy', function (done) {
            const cache = createErrorCodeCache();
            maxPasswordAge.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get account password policy', function (done) {
            const cache = createErrorCache();
            maxPasswordAge.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get account password policy response not found', function (done) {
            const cache = createNullCache();
            maxPasswordAge.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
