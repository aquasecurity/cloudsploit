var expect = require('chai').expect;
const minPasswordLength = require('./minPasswordLength');

const getAccountPasswordPolicy = [
    {
        "MinimumPasswordLength": 16,
        "RequireSymbols": false,
        "RequireNumbers": false,
        "RequireUppercaseCharacters": false,
        "RequireLowercaseCharacters": false,
        "AllowUsersToChangePassword": false,
        "ExpirePasswords": true,
        "MaxPasswordAge": 90
    },
    {
        "MinimumPasswordLength": 12,
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

const createCache = (policy) => {
    return {
        iam:{
            getAccountPasswordPolicy: {
                'us-east-1': {
                    data: policy
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
                        message: 'error getting account password policies'
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
                        message: 'error getting account password policies'
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

describe('minPasswordLength', function () {
    describe('run', function () {
        it('should PASS if minimum password length is suitable', function (done) {
            const cache = createCache(getAccountPasswordPolicy[0]);
            var settings = {
                min_password_length_fail: 10,
                min_password_length_warn: 14
            };
            minPasswordLength.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                done();
            });
        });

        it('should WARN if minimum password length is less than 14 characters', function (done) {
            const cache = createCache(getAccountPasswordPolicy[1]);
            var settings = {
                min_password_length_fail: 10,
                min_password_length_warn: 14
            };
            minPasswordLength.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(1);
                done();
            });
        });

        it('should FAIL if minimum password length is less than 10 characters', function (done) {
            const cache = createCache(getAccountPasswordPolicy[2]);
            var settings = {
                min_password_length_fail: 10,
                min_password_length_warn: 14
            };
            minPasswordLength.run(cache, settings, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if password policy does not specify a minimum password length', function (done) {
            const cache = createCache([]);
            minPasswordLength.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should FAIL if account does not have a password policy', function (done) {
            const cache = createErrorCodeCache();
            minPasswordLength.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                done();
            });
        });

        it('should UNKNOWN if unable to get account password policy', function (done) {
            const cache = createErrorCache();
            minPasswordLength.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                done();
            });
        });

        it('should not return anything if get account password policy response not found', function (done) {
            const cache = createNullCache();
            minPasswordLength.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(0);
                done();
            });
        });

    });
});
